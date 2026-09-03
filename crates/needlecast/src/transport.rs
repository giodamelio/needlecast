//! The `needle` interface, created and removed by needlecast itself.
//!
//! Nothing else on the machine is touched. The one sysctl — `route_localnet`, server only — lives
//! in a directory the kernel creates and destroys with the interface, so it cannot outlive us.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Context, Result};
use defguard_wireguard_rs::{
    key::Key, net::IpAddrMask, peer::Peer, InterfaceConfiguration, Kernel, WGApi,
    WireguardInterfaceApi,
};

use crate::identity::{Identity, Role};

/// `IF_NAMESIZE` is 16, so 15 characters are usable.
pub const IFACE: &str = "needle";

/// RFC 2544 benchmarking space: reserved, never routed, and not claimed by NAT gear or container
/// runtimes. Every other candidate is taken — see DESIGN.md, which rules out `169.254/16` at
/// length because the kernel hands those addresses out itself.
pub const SERVER_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
pub const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

/// A `/24` on the interface for the on-link route; a `/32` of `allowed-ips` for the peer.
const PREFIX_V4: u8 = 24;
const PEER_PREFIX_V4: u8 = 32;

const MTU: u32 = 1420;

/// Only has to be stable, not secret. Beside the control port so the two are obviously related.
pub const DEFAULT_LISTEN_PORT: u16 = 47654;

/// Client only: the server has the stable address, so holding the NAT hole open is our job.
const KEEPALIVE_SECS: u16 = 25;

/// The v6 halves are `None` until the server datapath speaks v6; the shape is here so that arrives
/// as new code rather than a change to everything that reads a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub own_v4: Ipv4Addr,
    pub peer_v4: Ipv4Addr,
    pub own_v6: Option<Ipv6Addr>,
    pub peer_v6: Option<Ipv6Addr>,
}

impl Plan {
    pub fn for_role(role: Role) -> Self {
        let (own_v4, peer_v4) = match role {
            Role::Server => (SERVER_V4, CLIENT_V4),
            Role::Client => (CLIENT_V4, SERVER_V4),
        };
        Plan {
            own_v4,
            peer_v4,
            own_v6: None,
            peer_v6: None,
        }
    }

    fn own_address(&self) -> IpAddrMask {
        IpAddrMask::new(IpAddr::V4(self.own_v4), PREFIX_V4)
    }

    fn peer_allowed_ips(&self) -> Vec<IpAddrMask> {
        let mut ips = vec![IpAddrMask::new(IpAddr::V4(self.peer_v4), PEER_PREFIX_V4)];
        if let Some(v6) = self.peer_v6 {
            ips.push(IpAddrMask::new(IpAddr::V6(v6), 128));
        }
        ips
    }
}

pub struct Tunnel {
    api: WGApi<Kernel>,
    plan: Plan,
    role: Role,
    private_key: Key,
    peer_key: Key,
    /// WireGuard resolves an endpoint once and holds it forever, so a peer that moves is
    /// unreachable until we re-resolve.
    endpoint: String,
    resolved: Option<SocketAddr>,
    listen_port: u16,
}

impl Tunnel {
    /// A leftover `needle` is replaced rather than adopted: the interface is ours alone, and a
    /// known-good one costs a single handshake where an inherited one costs unknown state.
    pub async fn up(identity: &Identity, peer_endpoint: &str, listen_port: u16) -> Result<Self> {
        let plan = Plan::for_role(identity.role);
        let mut api =
            WGApi::<Kernel>::new(IFACE.to_string()).context("opening the WireGuard netlink API")?;

        if interface_exists() {
            log::info!("{IFACE} already exists, replacing it");
            if let Err(e) = api.remove_interface() {
                log::warn!("could not remove the leftover {IFACE}: {e}");
            }
        }
        api.create_interface()
            .with_context(|| format!("creating {IFACE}"))?;

        let mut tunnel = Tunnel {
            api,
            plan,
            role: identity.role,
            private_key: Key::new(identity.private),
            peer_key: Key::new(identity.peer_public),
            endpoint: peer_endpoint.to_string(),
            resolved: None,
            listen_port,
        };
        // Not fatal: the interface is still worth having up so the peer can reach *us*.
        if let Err(e) = tunnel.resolve().await {
            log::warn!("could not resolve {peer_endpoint} yet: {e:#}");
        }
        tunnel.apply()?;

        if identity.role == Role::Server {
            set_route_localnet()?;
        }
        log::info!(
            "{IFACE} up as {} ({}), peer {} via {}",
            plan.own_v4,
            identity.role.name(),
            plan.peer_v4,
            peer_endpoint,
        );
        Ok(tunnel)
    }

    fn peer(&self) -> Peer {
        let mut peer = Peer::new(self.peer_key.clone());
        peer.set_allowed_ips(self.plan.peer_allowed_ips());
        peer.endpoint = self.resolved;
        if self.role == Role::Client {
            peer.persistent_keepalive_interval = Some(KEEPALIVE_SECS);
        }
        peer
    }

    fn apply(&self) -> Result<()> {
        let config = InterfaceConfiguration {
            name: IFACE.to_string(),
            prvkey: base64_key(&self.private_key),
            addresses: vec![self.plan.own_address()],
            port: self.listen_port,
            peers: vec![self.peer()],
            mtu: Some(MTU),
            fwmark: None,
        };
        self.api
            .configure_interface(&config)
            .with_context(|| format!("configuring {IFACE}"))?;
        Ok(())
    }

    /// Returns whether the address changed. Call on every reconnect attempt while disconnected,
    /// and every few minutes while connected.
    pub async fn refresh_endpoint(&mut self) -> Result<bool> {
        let previous = self.resolved;
        self.resolve().await?;
        if self.resolved == previous {
            return Ok(false);
        }
        log::info!(
            "{} resolved to {:?} (was {:?}), updating the peer",
            self.endpoint,
            self.resolved,
            previous
        );
        self.api
            .configure_peer(&self.peer())
            .context("updating the peer endpoint")?;
        Ok(true)
    }

    /// Resolution is async because a stalled DNS lookup on the single-threaded runtime would hold
    /// up the heartbeat, and a missed heartbeat is a reconnect nothing was wrong with.
    async fn resolve(&mut self) -> Result<()> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&self.endpoint)
            .await
            .with_context(|| format!("resolving {}", self.endpoint))?
            .collect();
        self.resolved = Some(
            pick_endpoint(&addrs)
                .ok_or_else(|| anyhow!("{} resolved to nothing", self.endpoint))?,
        );
        Ok(())
    }

    pub fn own_addr(&self) -> Ipv4Addr {
        self.plan.own_v4
    }

    pub fn peer_addr(&self) -> Ipv4Addr {
        self.plan.peer_v4
    }

    /// Consumes `self` so the `Drop` path cannot also run.
    pub fn down(self) -> Result<()> {
        let api = std::mem::ManuallyDrop::new(self);
        api.api
            .remove_interface()
            .with_context(|| format!("removing {IFACE}"))?;
        log::info!("{IFACE} removed");
        Ok(())
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if let Err(e) = self.api.remove_interface() {
            log::warn!("could not remove {IFACE} on shutdown: {e}");
        }
    }
}

/// Prefers IPv4: the tunnel is v4-only, and a machine publishing an AAAA it cannot be reached over
/// would leave the handshake failing with nothing to point at.
fn pick_endpoint(addrs: &[SocketAddr]) -> Option<SocketAddr> {
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
}

pub fn interface_exists() -> bool {
    std::path::Path::new(&format!("/sys/class/net/{IFACE}")).exists()
}

fn base64_key(key: &Key) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key.as_array())
}

/// Without this the rewritten packet is dropped as martian, which shows up as a hung connect
/// rather than a clean error. Scoped to our own interface; `all`, `default` and `lo` stay at `0`.
fn set_route_localnet() -> Result<()> {
    let path = format!("/proc/sys/net/ipv4/conf/{IFACE}/route_localnet");
    std::fs::write(&path, "1").with_context(|| format!("writing {path}"))?;
    log::info!("net.ipv4.conf.{IFACE}.route_localnet=1");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_roles_get_opposite_ends_of_the_same_plan() {
        let server = Plan::for_role(Role::Server);
        let client = Plan::for_role(Role::Client);
        assert_eq!(server.own_v4, client.peer_v4);
        assert_eq!(client.own_v4, server.peer_v4);
        assert_ne!(server.own_v4, client.own_v4);
    }

    #[test]
    fn the_addresses_are_in_rfc_2544_benchmarking_space() {
        for addr in [SERVER_V4, CLIENT_V4] {
            let o = addr.octets();
            assert_eq!(o[0], 198, "{addr} is outside 198.18.0.0/15");
            assert!((18..=19).contains(&o[1]), "{addr} is outside 198.18.0.0/15");
        }
    }

    #[test]
    fn the_addresses_avoid_every_range_the_design_ruled_out() {
        for addr in [SERVER_V4, CLIENT_V4] {
            assert!(!addr.is_private(), "{addr} is RFC 1918");
            assert!(!addr.is_link_local(), "{addr} is 169.254/16");
            assert!(!addr.is_loopback());
            let o = addr.octets();
            assert_ne!(o[0], 100, "{addr} is in CGNAT/Tailscale space");
            assert!(o[0] < 240, "{addr} is Class E");
        }
    }

    #[test]
    fn allowed_ips_is_the_peer_alone_not_the_whole_subnet() {
        let plan = Plan::for_role(Role::Server);
        let allowed = plan.peer_allowed_ips();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].address, IpAddr::V4(CLIENT_V4));
        assert_eq!(allowed[0].cidr, 32);
    }

    #[test]
    fn the_interface_address_carries_a_subnet() {
        let plan = Plan::for_role(Role::Client);
        assert_eq!(plan.own_address().cidr, PREFIX_V4);
        assert!(!plan.own_address().is_host());
    }

    #[test]
    fn a_v6_peer_would_be_allowed_alongside_v4_without_changing_the_v4_half() {
        let mut plan = Plan::for_role(Role::Server);
        plan.peer_v6 = Some("fd00::2".parse().unwrap());
        let allowed = plan.peer_allowed_ips();
        assert_eq!(allowed.len(), 2);
        assert_eq!(allowed[0].address, IpAddr::V4(CLIENT_V4));
        assert_eq!(allowed[1].cidr, 128);
    }

    #[test]
    fn the_interface_name_fits_in_if_namesize() {
        assert!(IFACE.len() < 16, "{IFACE} exceeds IF_NAMESIZE - 1");
    }

    #[test]
    fn the_two_fixed_ports_differ() {
        assert_ne!(
            DEFAULT_LISTEN_PORT,
            needlecast_common::proto::DEFAULT_CONTROL_PORT
        );
    }

    mod endpoint_selection {
        use super::*;

        fn v4(port: u16) -> SocketAddr {
            SocketAddr::from(([192, 168, 1, 2], port))
        }

        fn v6(port: u16) -> SocketAddr {
            SocketAddr::from(("2001:db8::2".parse::<Ipv6Addr>().unwrap(), port))
        }

        #[test]
        fn the_a_record_wins_even_when_the_aaaa_comes_first() {
            assert_eq!(pick_endpoint(&[v6(47654), v4(47654)]), Some(v4(47654)));
            assert_eq!(pick_endpoint(&[v4(47654), v6(47654)]), Some(v4(47654)));
        }

        #[test]
        fn a_v6_only_name_is_used_rather_than_refused() {
            assert_eq!(pick_endpoint(&[v6(47654)]), Some(v6(47654)));
        }

        #[test]
        fn the_first_of_several_a_records_is_chosen_deterministically() {
            let a = SocketAddr::from(([10, 0, 0, 1], 47654));
            let b = SocketAddr::from(([10, 0, 0, 2], 47654));
            assert_eq!(pick_endpoint(&[a, b]), Some(a));
        }

        #[test]
        fn nothing_resolved_is_an_absence_rather_than_a_wrong_answer() {
            assert_eq!(pick_endpoint(&[]), None);
        }
    }

    #[test]
    fn a_private_key_round_trips_through_wireguard_base64() {
        use base64::Engine;
        let raw = [7u8; 32];
        let encoded = base64_key(&Key::new(raw));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        assert_eq!(decoded, raw);
    }
}
