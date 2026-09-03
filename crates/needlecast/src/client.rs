//! The machine that types `localhost:8080` and means the other one.
//!
//! One thing here is load bearing: **on any error the enabled flag is cleared before anything
//! else**. A window where the programs rewrite toward a server known to be gone converts an
//! instant, correct `ECONNREFUSED` into a hang.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::Array;
use needlecast_common::proto::{wire, Msg};
use needlecast_common::{Config, CONFIG_KEY};

use crate::bpf;
use crate::control;
use crate::identity::{Identity, Role};
use crate::shutdown::Shutdown;
use crate::transport::Tunnel;
use crate::wake;

const BACKOFF_MIN: Duration = Duration::from_millis(200);
const BACKOFF_MAX: Duration = Duration::from_secs(5);

const ENDPOINT_REFRESH: Duration = Duration::from_secs(300);

/// How often the local network is re-examined. A poll because the snapshot is all `wake::Watch`
/// has to compare; Phase C replaces the timer with a netlink socket and keeps the comparison.
const WATCH_POLL: Duration = Duration::from_millis(250);

pub struct Args {
    pub secret: PathBuf,
    pub peer: String,
    pub listen_port: u16,
    pub control_port: u16,
    pub syncnt: u8,
}

pub async fn run(a: Args) -> Result<()> {
    let identity = Identity::load(&a.secret, Role::Client)?;
    let mut shutdown = Shutdown::install()?;

    let endpoint = format!("{}:{}", a.peer, a.listen_port);
    let mut tunnel = Tunnel::up(&identity, &endpoint, a.listen_port).await?;

    let bridge = Bridge::attach(tunnel.peer_addr(), a.syncnt)?;
    let control_addr = SocketAddr::from((tunnel.peer_addr(), a.control_port));

    let mut backoff = BACKOFF_MIN;
    let mut watch = wake::Watch::new();
    loop {
        // A moved peer is one of the two reasons a reconnect would otherwise never succeed.
        if let Err(e) = tunnel.refresh_endpoint().await {
            log::debug!("could not re-resolve {endpoint}: {e:#}");
        }

        match session(&mut tunnel, control_addr, &mut shutdown, &mut watch).await {
            Ok(Ended::Shutdown) => break,
            Ok(Ended::PeerGone) => log::info!("control connection closed"),
            Err(e) => {
                if let Some(m) = e.downcast_ref::<control::VersionMismatch>() {
                    log::error!("{m}");
                    bridge.disable();
                    drop(bridge);
                    let _ = tunnel.down();
                    std::process::exit(control::EXIT_VERSION_MISMATCH);
                }
                log::info!("control connection failed: {e:#}");
            }
        }

        bridge.disable();

        shutdown.sleep(backoff).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
        // The old connection is already dead, even though the socket does not know it yet.
        if let Some(reason) = watch.poll() {
            log::info!("{}, reconnecting now", reason.as_str());
            backoff = BACKOFF_MIN;
        }
    }

    log::info!("shutting down");
    bridge.disable();
    drop(bridge);
    tunnel.down()
}

enum Ended {
    PeerGone,
    Shutdown,
}

async fn session(
    tunnel: &mut Tunnel,
    addr: SocketAddr,
    shutdown: &mut Shutdown,
    watch: &mut wake::Watch,
) -> Result<Ended> {
    let s = control::dial(addr).await?;
    log::info!(
        "connected to {addr}, it serves ports {}-{}",
        s.port_lo,
        s.port_hi
    );
    // The server is authoritative over what it exposes.
    bpf::set_port_range(s.port_lo, s.port_hi)?;

    let (reader, mut writer) = s.stream.into_split();
    let mut frames = control::spawn_reader(reader);

    // Not enabled until the first listener snapshot, so the first connection after coming up is
    // decided on real information rather than an empty map.
    let mut ready = false;
    let mut heartbeat = control::Heartbeat::new(Instant::now());
    // Reads `/proc/net/tcp`, so it is on a timer rather than on every wakeup.
    let mut probe = tokio::time::interval(control::PING_INTERVAL);
    let mut resolve = tokio::time::interval(ENDPOINT_REFRESH);
    let mut network = tokio::time::interval(WATCH_POLL);
    resolve.reset();

    loop {
        tokio::select! {
            _ = shutdown.requested() => {
                let _ = wire::write(&mut writer, &Msg::Goodbye).await;
                return Ok(Ended::Shutdown);
            }
            frame = frames.recv() => {
                let Some(msg) = frame else { return Ok(Ended::PeerGone) };
                heartbeat.heard(Instant::now());
                match msg? {
                    Msg::Listeners { ports } => {
                        bpf::replace_listeners(&ports)?;
                        if !ready {
                            bpf::set_enabled(1)?;
                            ready = true;
                            log::info!("bridge enabled");
                        }
                        log::info!("the server serves {} ports in range", ports.len());
                    }
                    Msg::Goodbye => return Ok(Ended::PeerGone),
                    _ => {}
                }
            }
            _ = probe.tick() => {
                let was = heartbeat.interval();
                heartbeat.set_active(!control::established_with(tunnel.peer_addr()).is_empty());
                if heartbeat.interval() != was {
                    log::debug!("heartbeat now every {:?}", heartbeat.interval());
                }
            }
            // On its own timer: gating it on having received something deadlocks two idle peers.
            _ = tokio::time::sleep_until(heartbeat.next_wake().into()) => {
                match heartbeat.tick(Instant::now()) {
                    control::Beat::Ping => wire::write(&mut writer, &Msg::Ping).await?,
                    control::Beat::Expired => {
                        bail!("nothing heard within {:?}", heartbeat.deadline())
                    }
                    control::Beat::Wait => {}
                }
            }
            _ = network.tick() => {
                if let Some(reason) = watch.poll() {
                    bail!("{}", reason.as_str());
                }
            }
            _ = resolve.tick() => {
                if let Err(e) = tunnel.refresh_endpoint().await {
                    log::debug!("periodic re-resolve failed: {e:#}");
                }
            }
        }
    }
}

/// Dropping it, or dying, detaches every program and the machine reverts to stock.
pub struct Bridge {
    _ebpf: aya::Ebpf,
    _cgroup: std::fs::File,
}

impl Bridge {
    /// The flag first, always. Takes `&self` so it cannot be called on an already-detached bridge,
    /// where the maps are gone and there would be nothing to clear.
    pub fn disable(&self) {
        if let Err(e) = bpf::set_enabled(0).and_then(|()| bpf::clear_listeners()) {
            log::error!("failed to disable the bridge: {e:#}");
        }
    }
}

pub struct Attach {
    pub target_v4: Ipv4Addr,
    /// `None` on the shipped client, where `connect6` then declines rather than rewriting to `::`.
    pub target_v6: Option<Ipv6Addr>,
    pub syncnt: u8,
    pub port_lo: u16,
    pub port_hi: u16,
    pub netns_guard: bool,
    pub enabled: bool,
    /// Harness only. Kept separate so a verifier rejection is an observable result rather than
    /// something that takes the other eight programs down with it.
    pub syncnt_probe: bool,
}

impl Attach {
    /// Split out from the attach so its shape is testable without a kernel.
    fn config(&self, netns_cookie: u64) -> Config {
        Config {
            netns_cookie,
            target_v4: bpf::v4_be(self.target_v4),
            // All-zero means "decline IPv6" rather than "rewrite to ::".
            target_v6: self.target_v6.map(bpf::v6_words).unwrap_or([0; 4]),
            port_lo: self.port_lo,
            port_hi: self.port_hi,
            enabled: u8::from(self.enabled),
            use_listener_map: 1,
            syncnt: self.syncnt,
            _pad: 0,
        }
    }
}

impl Bridge {
    /// Starts disabled with an empty range, so before the control connection is up the machine
    /// behaves exactly as if needlecast were not installed.
    pub fn attach(target_v4: Ipv4Addr, syncnt: u8) -> Result<Self> {
        Self::attach_with(Attach {
            target_v4,
            target_v6: None,
            syncnt,
            port_lo: 0,
            port_hi: 0,
            netns_guard: true,
            enabled: false,
            syncnt_probe: false,
        })
    }

    pub fn attach_with(a: Attach) -> Result<Self> {
        bpf::reset_pin_dir(bpf::CLIENT_PIN_DIR)?;
        bpf::clear_ready(bpf::CLIENT_READY_FILE);

        let mut ebpf = bpf::load_object(bpf::CLIENT_PIN_DIR)?;
        let cgroup = std::fs::File::open(bpf::CGROUP_ROOT)
            .with_context(|| format!("opening {}", bpf::CGROUP_ROOT))?;

        let mut attached: Vec<&str> = bpf::CLIENT_PROGRAMS.to_vec();
        for name in bpf::CLIENT_PROGRAMS {
            bpf::attach_cgroup(&mut ebpf, name, &cgroup)
                .with_context(|| format!("attaching {name}"))?;
        }
        if a.syncnt_probe {
            match bpf::attach_cgroup(&mut ebpf, "connect4_syncnt_probe", &cgroup) {
                Ok(()) => attached.push("connect4_syncnt_probe"),
                Err(e) => log::warn!("connect4_syncnt_probe rejected: {e:#}"),
            }
        }

        let netns_cookie = if a.netns_guard {
            bpf::netns_cookie()?
        } else {
            0
        };
        let config = a.config(netns_cookie);
        let mut cfg_map: Array<_, Config> = ebpf
            .map_mut("CONFIG")
            .ok_or_else(|| anyhow!("CONFIG map missing"))?
            .try_into()?;
        cfg_map.set(CONFIG_KEY, config, 0)?;

        bpf::write_ready(
            bpf::CLIENT_READY_FILE,
            &format!(
                "target={}\nnetns_cookie={netns_cookie}\nsyncnt={}\nattached={}\n",
                a.target_v4,
                a.syncnt,
                attached.join(",")
            ),
        )?;
        log::info!(
            "bridge attached: {} programs, netns cookie {netns_cookie}, target {}",
            attached.len(),
            a.target_v4
        );
        println!("ready");

        Ok(Bridge {
            _ebpf: ebpf,
            _cgroup: cgroup,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use needlecast_common::net;

    fn shipped() -> Attach {
        Attach {
            target_v4: Ipv4Addr::new(198, 18, 0, 1),
            target_v6: None,
            syncnt: 2,
            port_lo: 0,
            port_hi: 0,
            netns_guard: true,
            enabled: false,
            syncnt_probe: false,
        }
    }

    #[test]
    fn the_bridge_starts_inert() {
        let c = shipped().config(1234);
        assert_eq!(
            c.enabled, 0,
            "nothing is rewritten until the server answers"
        );
        // An empty range declines every port on its own, so even a stray enable cannot forward.
        assert!(
            !net::port_in_range(8080, c.port_lo, c.port_hi),
            "the initial range should match nothing"
        );
    }

    #[test]
    fn the_range_arrives_from_the_server_rather_than_from_attach() {
        let c = shipped().config(1);
        assert_eq!((c.port_lo, c.port_hi), (0, 0));
    }

    #[test]
    fn no_v6_target_is_encoded_as_all_zero_words() {
        assert_eq!(shipped().config(1).target_v6, [0; 4]);
        let with_v6 = Attach {
            target_v6: Some("fd00:7::2".parse().unwrap()),
            ..shipped()
        };
        assert_ne!(with_v6.config(1).target_v6, [0; 4]);
    }

    #[test]
    fn the_target_is_stored_in_network_byte_order() {
        let c = shipped().config(1);
        assert_eq!(u32::from_be(c.target_v4), 0xC612_0001);
        assert!(!net::is_loopback_v4(c.target_v4));
    }

    #[test]
    fn the_netns_guard_is_the_captured_cookie() {
        assert_eq!(shipped().config(9876).netns_cookie, 9876);
        assert_eq!(shipped().config(0).netns_cookie, 0);
    }

    #[test]
    fn the_listener_map_is_always_consulted() {
        assert_eq!(shipped().config(1).use_listener_map, 1);
    }

    #[test]
    fn backoff_is_bounded_and_starts_small() {
        assert!(BACKOFF_MIN < BACKOFF_MAX);
        let mut b = BACKOFF_MIN;
        for _ in 0..20 {
            b = (b * 2).min(BACKOFF_MAX);
        }
        assert_eq!(b, BACKOFF_MAX, "backoff must converge, not grow forever");
    }

    #[test]
    fn the_endpoint_refresh_is_slower_than_the_heartbeat_but_not_indefinite() {
        assert!(ENDPOINT_REFRESH > control::IDLE_PING_INTERVAL);
        assert!(ENDPOINT_REFRESH <= Duration::from_secs(600));
    }
}
