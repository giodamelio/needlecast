//! The machine whose loopback ports are being reached.
//!
//! Stateless with respect to the client, so one that vanishes needs no cleanup: the tc programs
//! stay attached and simply never match.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, Context, Result};
use aya::programs::tc::{SchedClassifierLink, TcAttachType};
use aya::programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, TracePoint};
use needlecast_common::{FeedConfig, SleeveConfig};

use crate::bpf;
use crate::control;
use crate::identity::{Identity, Role};
use crate::shutdown::Shutdown;
use crate::transport::{self, Tunnel};

/// Not configurable: the point is that what a server is told is byte-identical to a genuinely
/// local connection. IPv6 has exactly one loopback address, so there is not even a range to pick
/// from as there is for v4.
const LOCAL_V4: Ipv4Addr = Ipv4Addr::LOCALHOST;
const LOCAL_V6: Ipv6Addr = Ipv6Addr::LOCALHOST;

pub struct Args {
    pub secret: std::path::PathBuf,
    pub peer: String,
    pub port_lo: u16,
    pub port_hi: u16,
    pub listen_port: u16,
    pub control_port: u16,
}

pub async fn run(a: Args) -> Result<()> {
    if a.port_lo > a.port_hi {
        bail!("--port-lo must not exceed --port-hi");
    }
    let identity = Identity::load(&a.secret, Role::Server)?;
    let mut shutdown = Shutdown::install()?;

    let endpoint = format!("{}:{}", a.peer, a.listen_port);
    let tunnel = Tunnel::up(&identity, &endpoint, a.listen_port).await?;

    let mut datapath = Datapath::attach(
        transport::IFACE,
        Sleeve {
            transport_v4: tunnel.own_addr(),
            transport_peer_v4: tunnel.peer_addr(),
            transport_v6: tunnel.own_addr_v6(),
            transport_peer_v6: tunnel.peer_addr_v6(),
            port_lo: a.port_lo,
            port_hi: a.port_hi,
            // Filled in by `attach`, which is the only place that can read them.
            l3_offset: 0,
            lo_ifindex: 0,
            v6_redirect: true,
        },
    )?;

    log::info!(
        "serving loopback ports {}-{} to {} on {}",
        a.port_lo,
        a.port_hi,
        tunnel.peer_addr(),
        transport::IFACE
    );
    let listeners = datapath.take_feed()?;
    control::serve(
        tunnel.own_addr(),
        a.control_port,
        a.port_lo,
        a.port_hi,
        listeners,
        &mut shutdown,
    )
    .await?;

    drop(datapath);
    tunnel.down()
}

/// What the datapath needs to know about the two ends of the tunnel.
pub struct Sleeve {
    pub transport_v4: Ipv4Addr,
    pub transport_peer_v4: Ipv4Addr,
    /// `None` leaves the v6 datapath off, and the tc programs pass IPv6 through untouched.
    pub transport_v6: Option<Ipv6Addr>,
    pub transport_peer_v6: Option<Ipv6Addr>,
    pub port_lo: u16,
    pub port_hi: u16,
    pub l3_offset: u16,
    pub lo_ifindex: u32,
    /// Always true in the product. See [`SleeveConfig::v6_redirect`].
    pub v6_redirect: bool,
}

/// Split out so its shape is testable without a kernel: a byte-order slip here would be invisible
/// until traffic failed to match.
fn sleeve_config(s: &Sleeve) -> SleeveConfig {
    SleeveConfig {
        transport_v4: bpf::v4_be(s.transport_v4),
        transport_peer_v4: bpf::v4_be(s.transport_peer_v4),
        local_v4: bpf::v4_be(LOCAL_V4),
        transport_v6: s.transport_v6.map(bpf::v6_words).unwrap_or([0; 4]),
        transport_peer_v6: s.transport_peer_v6.map(bpf::v6_words).unwrap_or([0; 4]),
        // Only meaningful alongside a v6 transport address, and all-zero is how the programs are
        // told the v6 datapath is off.
        local_v6: if s.transport_v6.is_some() {
            bpf::v6_words(LOCAL_V6)
        } else {
            [0; 4]
        },
        lo_ifindex: s.lo_ifindex,
        port_lo: s.port_lo,
        port_hi: s.port_hi,
        l3_offset: s.l3_offset,
        enabled: 1,
        v6_redirect: u8::from(s.v6_redirect),
    }
}

/// Dropping it, or dying, detaches every program and reverts the machine.
pub struct Datapath {
    ebpf: aya::Ebpf,
    _links: Vec<SchedClassifierLink>,
    _cgroup: std::fs::File,
}

impl Datapath {
    /// The ring buffer has one consumer, so it is handed over rather than shared.
    pub fn take_feed(&mut self) -> Result<control::Listeners> {
        let map = self
            .ebpf
            .take_map("LISTENER_EVENTS")
            .ok_or_else(|| anyhow!("LISTENER_EVENTS map missing"))?;
        control::spawn_feed(aya::maps::RingBuf::try_from(map)?)
    }
}

impl Datapath {
    pub fn attach(iface: &str, mut sleeve: Sleeve) -> Result<Self> {
        bpf::Half::Server.reset_pins()?;
        bpf::Half::Server.clear_ready();

        sleeve.l3_offset = bpf::l3_offset_for(iface)?;
        sleeve.lo_ifindex = bpf::loopback_ifindex()?;
        let l3_offset = sleeve.l3_offset;
        let mut ebpf = bpf::load_object(&bpf::Half::Server.pin_dir())?;

        // clsact must exist before either direction can attach; it may already be there.
        let _ = aya::programs::tc::qdisc_add_clsact(iface);

        let mut links = Vec::new();
        bpf::attach_tc(
            &mut ebpf,
            "tc_ingress",
            iface,
            TcAttachType::Ingress,
            &mut links,
        )?;
        bpf::attach_tc(
            &mut ebpf,
            "tc_egress",
            iface,
            TcAttachType::Egress,
            &mut links,
        )?;

        // The only programs outside the transport interface. They change nothing on the machine —
        // only what a server is told about its peer, and when userspace rescans its own listeners.
        let cgroup = std::fs::File::open(bpf::CGROUP_ROOT)
            .with_context(|| format!("opening {}", bpf::CGROUP_ROOT))?;
        for name in ["sleeve_getpeername4", "sleeve_getpeername6"] {
            let program: &mut CgroupSockAddr = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("{name} not found"))?
                .try_into()?;
            program.load().with_context(|| format!("loading {name}"))?;
            program
                .attach(&cgroup, CgroupAttachMode::Single)
                .with_context(|| format!("attaching {name}"))?;
        }

        let feed = FeedConfig {
            port_lo: sleeve.port_lo,
            port_hi: sleeve.port_hi,
            ..bpf::tracepoint_offsets()?
        };
        let mut feed_map: aya::maps::Array<_, FeedConfig> = ebpf
            .map_mut("FEED_CONFIG")
            .ok_or_else(|| anyhow!("FEED_CONFIG map missing"))?
            .try_into()?;
        feed_map.set(0, feed, 0)?;

        for name in ["listener_bind4", "listener_bind6", "listener_release"] {
            let program: &mut CgroupSock = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("{name} not found"))?
                .try_into()?;
            program.load().with_context(|| format!("loading {name}"))?;
            program
                .attach(&cgroup, CgroupAttachMode::Single)
                .with_context(|| format!("attaching {name}"))?;
        }
        let state: &mut TracePoint = ebpf
            .program_mut("listener_state")
            .ok_or_else(|| anyhow!("listener_state not found"))?
            .try_into()?;
        state.load().context("loading listener_state")?;
        state
            .attach("sock", "inet_sock_set_state")
            .context("attaching sock/inet_sock_set_state")?;

        let config = sleeve_config(&sleeve);
        let mut cfg_map: aya::maps::Array<_, SleeveConfig> = ebpf
            .map_mut("SLEEVE_CONFIG")
            .ok_or_else(|| anyhow!("SLEEVE_CONFIG map missing"))?
            .try_into()?;
        cfg_map.set(0, config, 0)?;

        let v6 = match (sleeve.transport_v6, sleeve.transport_peer_v6) {
            (Some(own), Some(peer)) => format!("transport_v6={own}\npeer_v6={peer}\n"),
            _ => String::from("transport_v6=none\n"),
        };
        bpf::Half::Server.write_ready(&format!(
            "iface={iface}\nl3_offset={l3_offset}\ntransport={}\npeer={}\n{v6}\
             ports={}-{}\nlo_ifindex={}\n\
             attached=tc_ingress,tc_egress,sleeve_getpeername4,sleeve_getpeername6,\
             listener_state,listener_bind4,listener_bind6,listener_release\n",
            sleeve.transport_v4,
            sleeve.transport_peer_v4,
            sleeve.port_lo,
            sleeve.port_hi,
            sleeve.lo_ifindex,
        ))?;
        log::info!("datapath attached to {iface}, L3 offset {l3_offset}");
        println!("ready");

        Ok(Datapath {
            ebpf,
            _links: links,
            _cgroup: cgroup,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use needlecast_common::net;

    fn sleeve(l3_offset: u16) -> Sleeve {
        Sleeve {
            transport_v4: Ipv4Addr::new(198, 18, 0, 1),
            transport_peer_v4: Ipv4Addr::new(198, 18, 0, 2),
            transport_v6: None,
            transport_peer_v6: None,
            port_lo: 8000,
            port_hi: 8999,
            l3_offset,
            lo_ifindex: 1,
            v6_redirect: true,
        }
    }

    fn cfg(l3_offset: u16) -> SleeveConfig {
        sleeve_config(&sleeve(l3_offset))
    }

    fn cfg6() -> SleeveConfig {
        sleeve_config(&Sleeve {
            transport_v6: Some("fdf0:2d9e:995e::1".parse().unwrap()),
            transport_peer_v6: Some("fdf0:2d9e:995e::2".parse().unwrap()),
            ..sleeve(0)
        })
    }

    /// A host-order slip would never match, and the datapath would silently pass everything.
    #[test]
    fn addresses_are_stored_in_network_byte_order() {
        let c = cfg(0);
        assert_eq!(u32::from_be(c.transport_v4), 0xC612_0001);
        assert_eq!(u32::from_be(c.transport_peer_v4), 0xC612_0002);
        assert_eq!(c.local_v4, net::LOOPBACK_V4);
    }

    #[test]
    fn delivery_is_always_plain_loopback() {
        assert_eq!(LOCAL_V4, Ipv4Addr::LOCALHOST);
        assert!(net::is_loopback_v4(cfg(0).local_v4));
    }

    /// 14 on an Ethernet-framed link, 0 on an L3-only one; one program serves both.
    #[test]
    fn the_l3_offset_is_carried_rather_than_guessed() {
        assert_eq!(cfg(0).l3_offset, 0);
        assert_eq!(cfg(14).l3_offset, 14);
    }

    #[test]
    fn the_managed_range_is_carried_verbatim() {
        let c = cfg(0);
        assert!(net::port_in_range(8000, c.port_lo, c.port_hi));
        assert!(net::port_in_range(8999, c.port_lo, c.port_hi));
        assert!(!net::port_in_range(7999, c.port_lo, c.port_hi));
        assert!(!net::port_in_range(9000, c.port_lo, c.port_hi));
    }

    /// Otherwise the datapath would rewrite the control plane's own packets.
    #[test]
    fn the_control_port_is_outside_the_range_it_serves() {
        let c = cfg(0);
        assert!(!net::port_in_range(
            needlecast_common::proto::DEFAULT_CONTROL_PORT,
            c.port_lo,
            c.port_hi
        ));
    }

    /// Unlike the client, it holds no state about the peer, so there is nothing to wait for.
    #[test]
    fn the_datapath_is_enabled_from_the_start() {
        assert_eq!(cfg(0).enabled, 1);
    }

    /// All-zero is how the tc programs are told to pass IPv6 through, so a pairing with no v6
    /// address must not accidentally configure `::` as the delivery target.
    #[test]
    fn without_a_v6_transport_address_every_v6_field_stays_zero() {
        let c = cfg(0);
        assert_eq!(c.transport_v6, [0; 4]);
        assert_eq!(c.transport_peer_v6, [0; 4]);
        assert_eq!(c.local_v6, [0; 4], "including the delivery address");
    }

    #[test]
    fn a_v6_transport_address_turns_on_loopback_delivery() {
        let c = cfg6();
        assert!(!net::v6_is_unspecified(&c.transport_v6));
        assert!(!net::v6_is_unspecified(&c.transport_peer_v6));
        assert_eq!(c.local_v6, bpf::v6_words(Ipv6Addr::LOCALHOST));
        assert!(net::is_loopback_v6(&c.local_v6));
        assert_ne!(c.transport_v6, c.transport_peer_v6);
    }

    /// The v6 addresses are stored as `bpf_sock_addr::user_ip6` does, or nothing would ever match.
    #[test]
    fn v6_addresses_are_stored_as_network_order_words() {
        let c = cfg6();
        assert_eq!(u32::from_be(c.transport_v6[0]), 0xfdf0_2d9e);
        assert_eq!(u32::from_be(c.transport_v6[3]), 1);
        assert_eq!(u32::from_be(c.transport_peer_v6[3]), 2);
    }

    /// The redirect target: a wrong ifindex would hand traffic to another device entirely.
    #[test]
    fn the_loopback_ifindex_is_carried_rather_than_assumed() {
        assert_eq!(cfg(0).lo_ifindex, 1);
    }
}
