//! The `needle` interface: created, configured, and removed by needlecast itself.
//!
//! Nothing else on the machine is touched. The one sysctl needed —
//! `net.ipv4.conf.needle.route_localnet=1`, and only on the server — lives in a directory the
//! kernel creates when the interface appears and destroys when it goes away, so it is a property of
//! our own interface rather than a machine setting, and it cannot outlive the daemon.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use anyhow::{anyhow, Context, Result};
use defguard_wireguard_rs::{
    key::Key, net::IpAddrMask, peer::Peer, InterfaceConfiguration, Kernel, WGApi,
    WireguardInterfaceApi,
};

use crate::identity::{Identity, Role};

/// `IF_NAMESIZE` is 16, so 15 characters are usable. Six is comfortable and unlikely to collide.
pub const IFACE: &str = "needle";

/// `198.18.0.0/15` is RFC 2544 space, reserved for benchmarking network equipment, and is the
/// best-kept-free range in IPv4. `10/8` and `192.168/16` are home routers and corporate VPNs;
/// Docker's bridge is `172.17/16` and compose walks up from `172.18`; `100.64/10` is CGNAT and
/// Tailscale; `240/4` is Class E, which many stacks refuse to route.
///
/// Not `169.254/16`: the kernel and DHCP clients hand those out themselves when DHCP fails, cloud
/// metadata lives at `169.254.169.254`, and `scope link` is not merely a label — source address
/// selection deprioritises it and several paths assume the destination is on the same segment.
pub const SERVER_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
pub const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

/// The address carries a `/24` so the on-link route exists; the peer's `allowed-ips` is a `/32`,
/// which is as tight as it can be with exactly one peer.
const PREFIX_V4: u8 = 24;
const PEER_PREFIX_V4: u8 = 32;

const MTU: u32 = 1420;

/// Only has to be stable and memorable, not secret. It sits beside the control port so the two are
/// obviously related.
pub const DEFAULT_LISTEN_PORT: u16 = 47654;

/// Sent by the client only. The server is the one with a stable address, so it is the client's job
/// to keep a path open through whatever NAT it is behind.
const KEEPALIVE_SECS: u16 = 25;

/// How the two ends address each other.
///
/// The v6 halves are `None` today: the desktop datapath is IPv4-only, and DESIGN.md's eventual
/// answer is a random IPv6 ULA `/48` rather than another well-known range. The shape is here so
/// that arrives as new code rather than as a change to everything that reads a plan.
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
    /// The peer's DNS name and port, kept so it can be resolved again. WireGuard resolves an
    /// endpoint once and then holds that address forever; if the peer moves, the tunnel is dead
    /// until something updates it. That something is us.
    endpoint: String,
    resolved: Option<SocketAddr>,
    listen_port: u16,
}

impl Tunnel {
    /// Brings the interface up. Idempotent: a leftover `needle` from a crashed run is replaced
    /// rather than adopted in whatever state it was left in, because the interface is ours alone
    /// and a known-good one costs a single handshake to re-establish.
    pub fn up(identity: &Identity, peer_endpoint: &str, listen_port: u16) -> Result<Self> {
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
            private_key: Key::new(identity.own.private),
            peer_key: Key::new(identity.peer.public),
            endpoint: peer_endpoint.to_string(),
            resolved: None,
            listen_port,
        };
        // Not fatal: the peer may simply not be resolvable yet, and the client retries on every
        // reconnect. The interface is still worth having up so the peer can reach *us*.
        if let Err(e) = tunnel.resolve() {
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

    /// Re-resolve the peer's name and update WireGuard if the answer changed.
    ///
    /// Returns whether it changed, so a caller can log a roam rather than a heartbeat. Call it on
    /// every reconnect attempt while disconnected, and every few minutes while connected.
    pub fn refresh_endpoint(&mut self) -> Result<bool> {
        let previous = self.resolved;
        self.resolve()?;
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

    fn resolve(&mut self) -> Result<()> {
        let addrs: Vec<SocketAddr> = self
            .endpoint
            .to_socket_addrs()
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

    /// A clean exit leaves no trace: no interface, no addresses, and the sysctl directory goes with
    /// it. Consumes `self` so the `Drop` path cannot also run.
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

/// Which resolved address to use as the WireGuard endpoint.
///
/// Prefers IPv4. The tunnel's own addressing is v4-only, and a machine that publishes an AAAA it
/// cannot actually be reached over would otherwise leave the handshake failing with nothing to
/// point at. A v6-only name still works — there is simply no better choice to make.
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

/// Without this the inbound packet is dropped as martian once its destination has been rewritten
/// to `127.0.0.1`, which shows up as a hung connect rather than a clean error.
///
/// Scoped to our own interface: `all`, `default` and `lo` stay at `0`, and the desktop suite
/// asserts that rather than leaving it to inspection. The blast radius is that packets *arriving on
/// `needle`* may address `127.0.0.0/8` — and the only thing that can put a packet there is a peer
/// that passed WireGuard's authentication, which is exactly what the server exists to serve.
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

    /// The ranges deliberately avoided, asserted so a future change to the constants cannot quietly
    /// land in one of them.
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

    /// A `/32` on the interface would leave no on-link route to the peer.
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

    /// The control port must not collide with the WireGuard port: one is inside the tunnel and one
    /// is on the internet, but a shared number would be a confusing coincidence at best.
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

        /// The case a real test found: the resolver answers with the AAAA first, and following it
        /// would leave the handshake failing on a machine reachable only over v4.
        #[test]
        fn the_a_record_wins_even_when_the_aaaa_comes_first() {
            assert_eq!(pick_endpoint(&[v6(47654), v4(47654)]), Some(v4(47654)));
            assert_eq!(pick_endpoint(&[v4(47654), v6(47654)]), Some(v4(47654)));
        }

        /// A v6-only name still works: there is simply no better choice to make.
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
