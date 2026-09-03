//! **No IPC dependency on the daemon**, because the moment this is worth having is the moment the
//! daemon is wedged or dead.
//!
//! Liveness comes from whether the programs are still *loaded*. The map pins are not evidence of
//! anything: they appear during load and survive a crash.

use std::time::SystemTime;

use anyhow::Result;
use aya::maps::{Array, Map};
use needlecast_common::{all_counters, all_tc_counters, Config, SleeveConfig};

use crate::bpf;
use crate::control;
use crate::transport;
use crate::StatusRole;

/// In the order they occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    NeverStarted,
    NotRunning,
    Disconnected,
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

/// Three independent observations, so no single stale artefact can produce a wrong answer alone.
pub fn classify(has_state: bool, programs_loaded: bool, enabled: Option<u8>) -> State {
    match (has_state, programs_loaded, enabled) {
        (false, false, _) => State::NeverStarted,
        (_, false, _) => State::NotRunning,
        (_, true, Some(1)) => State::Connected,
        (_, true, _) => State::Disconnected,
    }
}

/// `Auto` reports whichever half left state behind; naming a role reports it regardless, because
/// "nothing here" is then the answer you asked for.
fn which(role: StatusRole, client_state: bool, server_state: bool) -> (bool, bool) {
    match role {
        StatusRole::Auto => (client_state, server_state),
        StatusRole::Client => (true, false),
        StatusRole::Server => (false, true),
    }
}

pub fn report(role: StatusRole) -> Result<()> {
    let client_pins = bpf::Half::Client.has_pins();
    let server_pins = bpf::Half::Server.has_pins();
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
    let loaded = any_program_loaded(bpf::Half::Client.programs());
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
        bpf::Half::Client,
        "COUNTERS",
        all_counters().map(|(p, e, slot)| (p.as_str(), e.as_str(), slot)),
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
            any_program_loaded(bpf::Half::Server.programs()),
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
        bpf::Half::Server,
        "TC_COUNTERS",
        all_tc_counters().map(|(p, e, slot)| (p.as_str(), e.as_str(), slot)),
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

/// A tunnel that never handshook and one that handshook an hour ago are different problems.
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

/// The programs disappear with the process holding their links; the pins do not.
fn any_program_loaded(names: &[&str]) -> bool {
    aya::programs::loaded_programs()
        .filter_map(|p| p.ok())
        .any(|p| p.name_as_str().is_some_and(|n| names.contains(&n)))
}

fn read_client_config() -> Option<Config> {
    bpf::read_config().ok()
}

fn read_server_config() -> Option<SleeveConfig> {
    let m = bpf::Half::Server
        .open_map("SLEEVE_CONFIG", Map::Array)
        .ok()?;
    let map: Array<_, SleeveConfig> = (&m).try_into().ok()?;
    map.get(&0, 0).ok()
}

fn listener_ports() -> Vec<u16> {
    let Ok(m) = bpf::Half::Client.open_map("DESKTOP_PORTS", Map::HashMap) else {
        return Vec::new();
    };
    let Ok(map) = TryInto::<aya::maps::HashMap<_, u16, u8>>::try_into(&m) else {
        return Vec::new();
    };
    map.keys().filter_map(|k| k.ok()).collect()
}

fn print_counters(
    half: bpf::Half,
    name: &str,
    slots: impl Iterator<Item = (&'static str, &'static str, u32)>,
) {
    let Ok(m) = half.open_map(name, Map::Array) else {
        return;
    };
    let Ok(map) = TryInto::<Array<_, u64>>::try_into(&m) else {
        return;
    };
    for (prog_name, ev_name, slot) in slots {
        let v = map.get(&slot, 0).unwrap_or(0);
        if v != 0 {
            println!("counter.{prog_name}.{ev_name}={v}");
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

    /// Map pins survive a crash, so state on disk with no loaded programs means "it died".
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

        #[test]
        fn auto_reports_both_when_both_left_state_behind() {
            assert_eq!(which(StatusRole::Auto, true, true), (true, true));
        }

        #[test]
        fn a_named_role_is_reported_regardless() {
            assert_eq!(which(StatusRole::Client, false, false), (true, false));
            assert_eq!(which(StatusRole::Server, false, false), (false, true));
        }

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
