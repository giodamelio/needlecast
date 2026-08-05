//! `needlecast status` — what this machine is doing, read straight from the kernel.
//!
//! Deliberately takes **no IPC dependency on the daemon**, because the moment it is worth having is
//! exactly the moment the daemon is wedged or dead. Everything below comes from WireGuard over
//! netlink, the pinned BPF maps, `/proc/net/tcp`, and the loaded-program table.
//!
//! The map pins are not evidence of a running daemon: they appear during load and survive a crashed
//! process. Liveness comes from whether the programs are still loaded, because those disappear with
//! the process that holds their links.

use std::time::SystemTime;

use anyhow::Result;
use aya::maps::{Array, Map};
use needlecast_common::{
    counter_slot, ev, prog, tc, tc_counter_slot, tcev, Config, SleeveConfig, EV_NAMES, PROG_NAMES,
    TCEV_NAMES, TC_PROG_NAMES,
};

use crate::bpf;
use crate::control;
use crate::transport;
use crate::StatusRole;

/// The four states DESIGN.md distinguishes, in the order they occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No interface and no pinned maps: needlecast has not run here.
    NeverStarted,
    /// State on disk but no loaded programs: it ran and is not running now.
    NotRunning,
    /// Running, but the control connection is down, so nothing is being rewritten.
    Disconnected,
    /// Running with the bridge enabled.
    Connected,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::NeverStarted => "never-started",
            State::NotRunning => "not-running",
            State::Disconnected => "disconnected",
            State::Connected => "connected",
        }
    }
}

/// Decides the state from three independent observations, so that no single stale artefact can
/// produce a wrong answer on its own.
pub fn classify(has_state: bool, programs_loaded: bool, enabled: Option<u8>) -> State {
    match (has_state, programs_loaded, enabled) {
        (false, false, _) => State::NeverStarted,
        (_, false, _) => State::NotRunning,
        (_, true, Some(1)) => State::Connected,
        (_, true, _) => State::Disconnected,
    }
}

/// Which halves to report on. `Auto` shows whichever left state behind, so a machine that only ever
/// ran one does not get a section about the other; naming a role shows it regardless, because
/// "nothing here" is the answer you asked for.
fn which(role: StatusRole, client_state: bool, server_state: bool) -> (bool, bool) {
    match role {
        StatusRole::Auto => (client_state, server_state),
        StatusRole::Client => (true, false),
        StatusRole::Server => (false, true),
    }
}

pub fn report(role: StatusRole) -> Result<()> {
    let client_pins = std::path::Path::new(bpf::CLIENT_PIN_DIR).exists();
    let server_pins = std::path::Path::new(bpf::SERVER_PIN_DIR).exists();
    let (show_client, show_server) = which(role, client_pins, server_pins);

    if !show_client && !show_server {
        println!("state={}", State::NeverStarted.as_str());
        println!(
            "interface={}",
            if transport::interface_exists() {
                "up"
            } else {
                "absent"
            }
        );
        return Ok(());
    }

    if show_client {
        report_client(client_pins)?;
    }
    if show_server {
        report_server(server_pins)?;
    }
    report_tunnel();
    Ok(())
}

fn report_client(has_pins: bool) -> Result<()> {
    let config = read_client_config();
    let loaded = any_program_loaded(bpf::CLIENT_PROGRAMS);
    let state = classify(
        has_pins || transport::interface_exists(),
        loaded,
        config.as_ref().map(|c| c.enabled),
    );

    println!("role=client");
    println!("state={}", state.as_str());
    if let Some(c) = &config {
        println!(
            "target={}",
            std::net::Ipv4Addr::from(u32::from_be(c.target_v4))
        );
        println!("ports={}-{}", c.port_lo, c.port_hi);
        println!("enabled={}", c.enabled);
        let mut ports = listener_ports();
        ports.sort_unstable();
        println!(
            "server_listeners={}",
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        let peer = std::net::Ipv4Addr::from(u32::from_be(c.target_v4));
        for (local, remote) in control::established_with(peer) {
            println!("forwarded={local}->{peer}:{remote}");
        }
    }
    print_counters(
        bpf::CLIENT_PIN_DIR,
        "COUNTERS",
        prog::COUNT,
        ev::COUNT,
        |p, e| {
            (
                PROG_NAMES[p as usize],
                EV_NAMES[e as usize],
                counter_slot(p, e),
            )
        },
    );
    Ok(())
}

fn report_server(has_pins: bool) -> Result<()> {
    let config = read_server_config();
    println!("role=server");
    println!(
        "state={}",
        classify(
            has_pins || transport::interface_exists(),
            any_program_loaded(bpf::SERVER_PROGRAMS),
            config.as_ref().map(|c| c.enabled),
        )
        .as_str()
    );
    if let Some(c) = &config {
        println!("ports={}-{}", c.port_lo, c.port_hi);
        println!(
            "peer={}",
            std::net::Ipv4Addr::from(u32::from_be(c.transport_peer_v4))
        );
        match control::local_listeners() {
            Ok(all) => {
                let served: Vec<String> = all
                    .into_iter()
                    .filter(|p| *p >= c.port_lo && *p <= c.port_hi)
                    .map(|p| p.to_string())
                    .collect();
                println!("serving={}", served.join(","));
            }
            Err(e) => println!("serving=unknown ({e})"),
        }
    }
    print_counters(
        bpf::SERVER_PIN_DIR,
        "TC_COUNTERS",
        tc::COUNT,
        tcev::COUNT,
        |p, e| {
            (
                TC_PROG_NAMES[p as usize],
                TCEV_NAMES[e as usize],
                tc_counter_slot(p, e),
            )
        },
    );
    Ok(())
}

fn report_tunnel() {
    if !transport::interface_exists() {
        println!("interface=absent");
        return;
    }
    println!("interface={}", transport::IFACE);
    let api = match defguard_wireguard_rs::WGApi::<defguard_wireguard_rs::Kernel>::new(
        transport::IFACE.to_string(),
    ) {
        Ok(api) => api,
        Err(e) => {
            println!("wireguard=unreadable ({e})");
            return;
        }
    };
    use defguard_wireguard_rs::WireguardInterfaceApi;
    match api.read_interface_data() {
        Ok(host) => {
            println!("listen_port={}", host.listen_port);
            for peer in host.peers.values() {
                println!(
                    "peer_endpoint={}",
                    peer.endpoint
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "unresolved".into())
                );
                println!("handshake={}", handshake_age(peer.last_handshake));
                println!("rx_bytes={} tx_bytes={}", peer.rx_bytes, peer.tx_bytes);
            }
        }
        Err(e) => println!("wireguard=unreadable ({e})"),
    }
}

/// Seconds since the last handshake, or `never`. A tunnel that has never handshaken and one that
/// handshook an hour ago are different problems.
fn handshake_age(last: Option<SystemTime>) -> String {
    match last {
        None => "never".to_string(),
        Some(t) if t == SystemTime::UNIX_EPOCH => "never".to_string(),
        Some(t) => match t.elapsed() {
            Ok(d) => format!("{}s ago", d.as_secs()),
            Err(_) => "in the future".to_string(),
        },
    }
}

/// The programs disappear with the process holding their links, so this — not the presence of a
/// pin, which survives a crash — is what distinguishes a running daemon from a dead one.
fn any_program_loaded(names: &[&str]) -> bool {
    aya::programs::loaded_programs()
        .filter_map(|p| p.ok())
        .any(|p| p.name_as_str().is_some_and(|n| names.contains(&n)))
}

fn read_client_config() -> Option<Config> {
    bpf::read_config().ok()
}

fn read_server_config() -> Option<SleeveConfig> {
    let m = bpf::open_pinned(bpf::SERVER_PIN_DIR, "SLEEVE_CONFIG", Map::Array).ok()?;
    let map: Array<_, SleeveConfig> = (&m).try_into().ok()?;
    map.get(&0, 0).ok()
}

fn listener_ports() -> Vec<u16> {
    let Ok(m) = bpf::open_pinned(bpf::CLIENT_PIN_DIR, "DESKTOP_PORTS", Map::HashMap) else {
        return Vec::new();
    };
    let Ok(map) = TryInto::<aya::maps::HashMap<_, u16, u8>>::try_into(&m) else {
        return Vec::new();
    };
    map.keys().filter_map(|k| k.ok()).collect()
}

fn print_counters(
    dir: &str,
    name: &str,
    progs: u32,
    events: u32,
    describe: impl Fn(u32, u32) -> (&'static str, &'static str, u32),
) {
    let Ok(m) = bpf::open_pinned(dir, name, Map::Array) else {
        return;
    };
    let Ok(map) = TryInto::<Array<_, u64>>::try_into(&m) else {
        return;
    };
    for p in 0..progs {
        for e in 0..events {
            let (prog_name, ev_name, slot) = describe(p, e);
            let v = map.get(&slot, 0).unwrap_or(0);
            if v != 0 {
                println!("counter.{prog_name}.{ev_name}={v}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_on_disk_and_nothing_loaded_is_never_started() {
        assert_eq!(classify(false, false, None), State::NeverStarted);
    }

    /// The distinction that matters: map pins survive a crashed process, so state on disk with no
    /// loaded programs is "it died", not "it is running but idle".
    #[test]
    fn state_on_disk_without_loaded_programs_is_not_running() {
        assert_eq!(classify(true, false, None), State::NotRunning);
        assert_eq!(classify(true, false, Some(1)), State::NotRunning);
        assert_eq!(classify(true, false, Some(0)), State::NotRunning);
    }

    #[test]
    fn loaded_but_not_enabled_is_disconnected() {
        assert_eq!(classify(true, true, Some(0)), State::Disconnected);
        assert_eq!(classify(true, true, None), State::Disconnected);
    }

    #[test]
    fn loaded_and_enabled_is_connected() {
        assert_eq!(classify(true, true, Some(1)), State::Connected);
    }

    #[test]
    fn every_state_has_a_distinct_name() {
        let names: Vec<&str> = [
            State::NeverStarted,
            State::NotRunning,
            State::Disconnected,
            State::Connected,
        ]
        .iter()
        .map(|s| s.as_str())
        .collect();
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(names.len(), unique.len(), "{names:?}");
    }

    mod which_halves {
        use super::*;

        #[test]
        fn auto_reports_only_what_actually_ran_here() {
            assert_eq!(which(StatusRole::Auto, true, false), (true, false));
            assert_eq!(which(StatusRole::Auto, false, true), (false, true));
            assert_eq!(which(StatusRole::Auto, false, false), (false, false));
        }

        /// Both halves on one machine would fight over `needle`, but `status` still reports what
        /// it finds rather than deciding the situation is impossible.
        #[test]
        fn auto_reports_both_when_both_left_state_behind() {
            assert_eq!(which(StatusRole::Auto, true, true), (true, true));
        }

        /// Naming a role reports it even with nothing on disk: "never started" is the answer.
        #[test]
        fn a_named_role_is_reported_regardless() {
            assert_eq!(which(StatusRole::Client, false, false), (true, false));
            assert_eq!(which(StatusRole::Server, false, false), (false, true));
        }

        /// And naming one role never drags in the other.
        #[test]
        fn a_named_role_excludes_the_other() {
            assert_eq!(which(StatusRole::Client, true, true), (true, false));
            assert_eq!(which(StatusRole::Server, true, true), (false, true));
        }
    }

    #[test]
    fn a_missing_handshake_reads_as_never_not_as_a_huge_age() {
        assert_eq!(handshake_age(None), "never");
        assert_eq!(handshake_age(Some(SystemTime::UNIX_EPOCH)), "never");
    }

    #[test]
    fn a_recent_handshake_reads_in_seconds() {
        let t = SystemTime::now() - std::time::Duration::from_secs(5);
        let s = handshake_age(Some(t));
        assert!(s.ends_with("s ago"), "{s}");
        let secs: u64 = s.trim_end_matches("s ago").parse().unwrap();
        assert!((4..=7).contains(&secs), "{s}");
    }
}
