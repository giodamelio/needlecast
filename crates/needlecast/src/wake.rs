//! Backoff is right when the peer is merely down, and wrong when the *local* machine just changed
//! underneath the connection — the socket does not know it is dead yet, and sleeping out the
//! backoff wastes the exact moment someone is waiting on.
//!
//! Netlink says *when* to look; the address and route snapshots below say whether anything we care
//! about actually moved. Keeping the two separate is what stops `needle` coming up — a change we
//! made ourselves — from counting as news.

use std::collections::BTreeSet;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use anyhow::{Context, Result};

/// Only used for a log line, but a specific one beats "retrying" — and netlink knows which of the
/// three it was, so there is no reason to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Resumed,
    LinkChanged,
    AddressChanged,
    RouteChanged,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Resumed => "resumed from suspend",
            Reason::LinkChanged => "a local link changed",
            Reason::AddressChanged => "a local address changed",
            Reason::RouteChanged => "the local routing table changed",
        }
    }
}

/// Which kinds of message arrived. Several can be true at once — bringing an interface up produces
/// all three — so the reason reported is the most specific one that fired.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Change {
    pub link: bool,
    pub address: bool,
    pub route: bool,
}

impl Change {
    /// Address first: it is the one that actually invalidates a socket. A route change without one
    /// is a different network for the same address, which matters second.
    fn reason(self) -> Option<Reason> {
        if self.address {
            Some(Reason::AddressChanged)
        } else if self.route {
            Some(Reason::RouteChanged)
        } else if self.link {
            Some(Reason::LinkChanged)
        } else {
            None
        }
    }

    fn everything() -> Self {
        Change {
            link: true,
            address: true,
            route: true,
        }
    }
}

pub struct Watch {
    suspended: Duration,
    addresses: BTreeSet<String>,
    routes: u64,
}

impl Watch {
    pub fn new() -> Self {
        Watch {
            suspended: suspended_time(),
            addresses: local_addresses(),
            routes: route_fingerprint(),
        }
    }

    /// Called when netlink reported something. `None` means nothing we depend on moved — which is
    /// the common case, because our own interface generates messages too.
    pub fn network_changed(&mut self, change: Change) -> Option<Reason> {
        let reason = change.reason()?;
        let addresses = local_addresses();
        let routes = route_fingerprint();
        if addresses == self.addresses && routes == self.routes {
            return None;
        }
        self.addresses = addresses;
        self.routes = routes;
        Some(reason)
    }

    /// Needs no timer of its own: any existing wakeup will do, and the heartbeat is never further
    /// off than thirty seconds. Nobody is waiting during the gap, because a machine that just woke
    /// has nothing in flight.
    ///
    /// `CLOCK_MONOTONIC` stops while suspended and `CLOCK_BOOTTIME` does not, so the gap between
    /// them *is* time spent suspended — resume detection with no systemd integration.
    pub fn resumed(&mut self) -> Option<Reason> {
        let suspended = suspended_time();
        let slept = suspended.saturating_sub(self.suspended);
        self.suspended = suspended;
        if slept < RESUME_THRESHOLD {
            return None;
        }
        // Resuming almost always renumbers, so refresh both baselines rather than reporting a
        // network change immediately afterwards as well.
        self.addresses = local_addresses();
        self.routes = route_fingerprint();
        Some(Reason::Resumed)
    }
}

impl Default for Watch {
    fn default() -> Self {
        Self::new()
    }
}

/// A read-only `NETLINK_ROUTE` socket. Nothing is ever sent on it; it exists to become readable.
pub struct Monitor(OwnedFd);

impl Monitor {
    pub fn open() -> Result<Self> {
        // SAFETY: a plain socket(2), checked below. `SOCK_NONBLOCK` because the fd is handed to a
        // reactor, and `SOCK_CLOEXEC` so it cannot leak into anything the daemon spawns.
        let fd: RawFd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("opening a netlink socket");
        }
        // SAFETY: `fd` is a fresh descriptor this function owns.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_groups = (libc::RTMGRP_LINK
            | libc::RTMGRP_IPV4_IFADDR
            | libc::RTMGRP_IPV6_IFADDR
            | libc::RTMGRP_IPV4_ROUTE
            | libc::RTMGRP_IPV6_ROUTE) as u32;
        // SAFETY: `addr` is a correctly sized, zero-initialised `sockaddr_nl`.
        let rc = unsafe {
            libc::bind(
                owned.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("subscribing to netlink groups");
        }
        Ok(Monitor(owned))
    }

    /// Reads until the socket is empty, reporting only *what kind* of thing happened. The payloads
    /// are never parsed: `Watch` re-reads the real state, which is both simpler and more honest
    /// than reconstructing it from a message stream.
    pub fn drain(&self) -> Change {
        let mut change = Change::default();
        let mut buf = [0u8; 8192];
        loop {
            // SAFETY: writing into a local buffer of exactly the length passed.
            let n = unsafe {
                libc::recv(
                    self.0.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n <= 0 {
                let err = std::io::Error::last_os_error();
                // A full receive queue means messages were lost, so the only safe reading is that
                // anything might have changed. `Watch` still decides whether it mattered.
                if n < 0 && err.raw_os_error() == Some(libc::ENOBUFS) {
                    log::debug!("netlink overran; assuming everything changed");
                    return Change::everything();
                }
                return change;
            }
            classify(&buf[..n as usize], &mut change);
        }
    }
}

impl AsRawFd for Monitor {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Walks the `nlmsghdr` chain far enough to read each message's type and no further.
fn classify(mut buf: &[u8], change: &mut Change) {
    const HDR: usize = 16;
    while buf.len() >= HDR {
        let len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let kind = u16::from_ne_bytes([buf[4], buf[5]]);
        match kind {
            libc::RTM_NEWLINK | libc::RTM_DELLINK => change.link = true,
            libc::RTM_NEWADDR | libc::RTM_DELADDR => change.address = true,
            libc::RTM_NEWROUTE | libc::RTM_DELROUTE => change.route = true,
            _ => {}
        }
        // A length below the header size would not advance the cursor, so stop rather than spin.
        // The aligned step is checked too, since it can exceed the buffer where `len` does not.
        let step = (len + 3) & !3;
        if len < HDR || step > buf.len() {
            return;
        }
        buf = &buf[step..];
    }
}

/// Below this it is scheduling noise rather than a suspend.
const RESUME_THRESHOLD: Duration = Duration::from_secs(2);

fn clock(id: libc::clockid_t) -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Cannot fail for these clock ids on any kernel that runs eBPF.
    unsafe { libc::clock_gettime(id, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// `CLOCK_MONOTONIC` is read first on purpose. The two reads are microseconds apart, and on a
/// machine that has never suspended the gap is zero — so reading `CLOCK_BOOTTIME` first makes the
/// subtraction underflow every time, and `saturating_sub` then reports zero forever.
fn suspended_time() -> Duration {
    let monotonic = clock(libc::CLOCK_MONOTONIC);
    clock(libc::CLOCK_BOOTTIME).saturating_sub(monotonic)
}

/// `needle` and `lo` are excluded: a change we made ourselves is not news.
fn local_addresses() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let entry = &*cur;
            cur = entry.ifa_next;
            if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(entry.ifa_name).to_string_lossy();
            if name == crate::transport::IFACE || name == "lo" {
                continue;
            }
            let Some(addr) = sockaddr_text(entry.ifa_addr) else {
                continue;
            };
            out.insert(format!("{name}/{addr}"));
        }
        libc::freeifaddrs(head);
    }
    out
}

unsafe fn sockaddr_text(sa: *const libc::sockaddr) -> Option<String> {
    match (*sa).sa_family as libc::c_int {
        libc::AF_INET => {
            let v4 = &*(sa as *const libc::sockaddr_in);
            Some(std::net::Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr)).to_string())
        }
        libc::AF_INET6 => {
            let v6 = &*(sa as *const libc::sockaddr_in6);
            Some(std::net::Ipv6Addr::from(v6.sin6_addr.s6_addr).to_string())
        }
        _ => None,
    }
}

/// A changed default route is the clearest "different network now" signal, and `/proc/net/route`
/// shows it without a netlink socket.
fn route_fingerprint() -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/net/route") else {
        return 0;
    };
    fingerprint_routes(&text)
}

fn fingerprint_routes(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for line in text.lines().skip(1) {
        let mut f = line.split_whitespace();
        let (Some(iface), Some(dest), Some(gateway)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if iface == crate::transport::IFACE {
            continue;
        }
        (iface, dest, gateway).hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only holds in this order, which is why `suspended_time` reads them this way round.
    #[test]
    fn boottime_is_never_behind_monotonic_read_earlier() {
        let monotonic = clock(libc::CLOCK_MONOTONIC);
        assert!(clock(libc::CLOCK_BOOTTIME) >= monotonic);
    }

    /// `poll` compares consecutive readings, so a gap that drifts on its own is a resume reported
    /// on a machine that never slept.
    #[test]
    fn the_suspend_gap_holds_still_while_the_machine_is_awake() {
        let first = suspended_time();
        std::thread::sleep(Duration::from_millis(50));
        let second = suspended_time();
        assert!(
            second.abs_diff(first) < RESUME_THRESHOLD,
            "gap drifted from {first:?} to {second:?}"
        );
    }

    #[test]
    fn a_quiet_machine_reports_no_reason_to_wake() {
        let mut watch = Watch::new();
        assert_eq!(watch.resumed(), None);
        // Netlink fired, but nothing this machine depends on actually moved.
        assert_eq!(watch.network_changed(Change::everything()), None);
        assert_eq!(watch.network_changed(Change::default()), None);
    }

    #[test]
    fn the_local_address_set_is_readable_and_excludes_loopback() {
        let addrs = local_addresses();
        assert!(
            addrs.iter().all(|a| !a.starts_with("lo/")),
            "loopback leaked into the fingerprint: {addrs:?}"
        );
    }

    #[test]
    fn route_fingerprints_differ_when_the_default_route_moves() {
        let header = "Iface\tDestination\tGateway\tFlags\n";
        let wifi = format!("{header}wlan0\t00000000\t0101A8C0\t0003\n");
        let wired = format!("{header}eth0\t00000000\t0101A8C0\t0003\n");
        let moved = format!("{header}wlan0\t00000000\tFE01A8C0\t0003\n");
        assert_ne!(fingerprint_routes(&wifi), fingerprint_routes(&wired));
        assert_ne!(fingerprint_routes(&wifi), fingerprint_routes(&moved));
        assert_eq!(fingerprint_routes(&wifi), fingerprint_routes(&wifi.clone()));
    }

    #[test]
    fn our_own_interface_is_excluded_from_the_route_fingerprint() {
        let header = "Iface\tDestination\tGateway\tFlags\n";
        let without = format!("{header}eth0\t00000000\t0101A8C0\t0003\n");
        let with =
            format!("{header}eth0\t00000000\t0101A8C0\t0003\nneedle\t000012C6\t00000000\t0001\n");
        assert_eq!(fingerprint_routes(&without), fingerprint_routes(&with));
    }

    #[test]
    fn a_header_only_route_table_fingerprints_consistently() {
        assert_eq!(fingerprint_routes("Iface\tDest\n"), fingerprint_routes(""));
    }

    #[test]
    fn reasons_describe_themselves() {
        assert!(Reason::Resumed.as_str().contains("suspend"));
        assert!(Reason::LinkChanged.as_str().contains("link"));
        assert!(Reason::AddressChanged.as_str().contains("address"));
        assert!(Reason::RouteChanged.as_str().contains("routing"));
    }

    /// An address disappearing is what invalidates a socket, so it outranks the route change that
    /// comes with it and the link change that comes with both.
    #[test]
    fn the_most_specific_reason_wins() {
        let all = Change::everything();
        assert_eq!(all.reason(), Some(Reason::AddressChanged));
        assert_eq!(
            Change {
                route: true,
                link: true,
                ..Default::default()
            }
            .reason(),
            Some(Reason::RouteChanged)
        );
        assert_eq!(
            Change {
                link: true,
                ..Default::default()
            }
            .reason(),
            Some(Reason::LinkChanged)
        );
        assert_eq!(Change::default().reason(), None);
    }

    mod netlink {
        use super::*;

        /// `nlmsghdr` is `{ len: u32, type: u16, flags: u16, seq: u32, pid: u32 }`.
        fn msg(kind: u16, payload: usize) -> Vec<u8> {
            let len = 16 + payload;
            let mut v = (len as u32).to_ne_bytes().to_vec();
            v.extend_from_slice(&kind.to_ne_bytes());
            v.extend_from_slice(&0u16.to_ne_bytes());
            v.extend_from_slice(&0u32.to_ne_bytes());
            v.extend_from_slice(&0u32.to_ne_bytes());
            v.resize(((len + 3) & !3).max(16), 0);
            v
        }

        #[test]
        fn each_message_type_maps_to_its_own_kind_of_change() {
            for (kind, want) in [
                (
                    libc::RTM_NEWLINK,
                    Change {
                        link: true,
                        ..Default::default()
                    },
                ),
                (
                    libc::RTM_DELLINK,
                    Change {
                        link: true,
                        ..Default::default()
                    },
                ),
                (
                    libc::RTM_NEWADDR,
                    Change {
                        address: true,
                        ..Default::default()
                    },
                ),
                (
                    libc::RTM_DELADDR,
                    Change {
                        address: true,
                        ..Default::default()
                    },
                ),
                (
                    libc::RTM_NEWROUTE,
                    Change {
                        route: true,
                        ..Default::default()
                    },
                ),
                (
                    libc::RTM_DELROUTE,
                    Change {
                        route: true,
                        ..Default::default()
                    },
                ),
            ] {
                let mut got = Change::default();
                classify(&msg(kind, 24), &mut got);
                assert_eq!(got, want, "message type {kind}");
            }
        }

        /// One `recv` returns several messages, and bringing an interface up produces all three.
        #[test]
        fn a_batch_is_walked_to_the_end() {
            let mut buf = msg(libc::RTM_NEWLINK, 16);
            buf.extend(msg(libc::RTM_NEWADDR, 20));
            buf.extend(msg(libc::RTM_NEWROUTE, 8));
            let mut got = Change::default();
            classify(&buf, &mut got);
            assert_eq!(got, Change::everything());
        }

        /// Unaligned payloads are padded to four bytes, so the walk must round up or it lands
        /// mid-header and reads garbage as a message type.
        #[test]
        fn the_walk_respects_four_byte_alignment() {
            let mut buf = msg(libc::RTM_NEWADDR, 5);
            buf.extend(msg(libc::RTM_NEWROUTE, 8));
            let mut got = Change::default();
            classify(&buf, &mut got);
            assert!(got.address && got.route, "{got:?}");
        }

        /// A short read or a corrupt length must stop the walk rather than spin or panic.
        #[test]
        fn a_malformed_message_stops_the_walk_without_panicking() {
            let mut got = Change::default();
            classify(&[], &mut got);
            classify(&[0u8; 7], &mut got);
            assert_eq!(got, Change::default());

            // A length inside the header size would never advance the cursor.
            let mut zero_len = msg(libc::RTM_NEWADDR, 24);
            zero_len[..4].copy_from_slice(&0u32.to_ne_bytes());
            classify(&zero_len, &mut got);
            assert_eq!(
                got,
                Change {
                    address: true,
                    ..Default::default()
                }
            );

            // A length past the end of the buffer.
            let mut too_long = msg(libc::RTM_NEWROUTE, 24);
            too_long[..4].copy_from_slice(&9999u32.to_ne_bytes());
            let mut got = Change::default();
            classify(&too_long, &mut got);
            assert_eq!(
                got,
                Change {
                    route: true,
                    ..Default::default()
                }
            );
        }

        #[test]
        fn unrelated_message_types_are_ignored() {
            let mut got = Change::default();
            classify(&msg(libc::RTM_NEWQDISC, 16), &mut got);
            classify(&msg(libc::NLMSG_DONE as u16, 0), &mut got);
            assert_eq!(got, Change::default());
        }

        /// The socket is opened by the daemon before anything else, so a failure here is a startup
        /// failure rather than a silent loss of the feature.
        #[test]
        fn the_monitor_opens_and_subscribes() {
            let m = Monitor::open().expect("netlink is available to an unprivileged process");
            assert!(m.as_raw_fd() >= 0);
            // Nothing has happened, and it is non-blocking, so this returns rather than hanging.
            assert_eq!(m.drain(), Change::default());
        }
    }
}
