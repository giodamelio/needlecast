//! Two signals that make waiting pointless, so the client can reconnect promptly rather than
//! eventually.
//!
//! Backoff is the right default when a peer is merely down. It is the wrong answer when the *local*
//! machine just changed underneath the connection: the socket does not know it is dead yet, and
//! sleeping out the backoff wastes the exact moment the user is waiting on.

use std::collections::BTreeSet;
use std::time::Duration;

/// What woke us. Only used for a log line, but a specific one beats "retrying".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Resumed,
    NetworkChanged,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Resumed => "resumed from suspend",
            Reason::NetworkChanged => "local network changed",
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

    /// Anything worth abandoning the backoff for. Cheap enough to call on every loop tick.
    pub fn poll(&mut self) -> Option<Reason> {
        // CLOCK_MONOTONIC stops while suspended and CLOCK_BOOTTIME does not, so the gap between
        // them *is* time spent suspended. A jump in it detects resume with no systemd integration
        // and no new dependency.
        let suspended = suspended_time();
        if suspended.saturating_sub(self.suspended) >= RESUME_THRESHOLD {
            self.suspended = suspended;
            // Coming back from suspend almost always renumbers, so refresh both baselines rather
            // than reporting a network change on the next tick as well.
            self.addresses = local_addresses();
            self.routes = route_fingerprint();
            return Some(Reason::Resumed);
        }
        self.suspended = suspended;

        let addresses = local_addresses();
        let routes = route_fingerprint();
        if addresses != self.addresses || routes != self.routes {
            self.addresses = addresses;
            self.routes = routes;
            return Some(Reason::NetworkChanged);
        }
        None
    }
}

impl Default for Watch {
    fn default() -> Self {
        Self::new()
    }
}

/// Below this, the difference is scheduling noise rather than a suspend.
const RESUME_THRESHOLD: Duration = Duration::from_secs(2);

fn clock(id: libc::clockid_t) -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Cannot fail for these two clock ids on any kernel that runs eBPF.
    unsafe { libc::clock_gettime(id, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

fn suspended_time() -> Duration {
    clock(libc::CLOCK_BOOTTIME).saturating_sub(clock(libc::CLOCK_MONOTONIC))
}

/// Every address on every interface, as `iface/address`. `needle` is excluded: needlecast changes
/// that one itself, and a change we made is not news.
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

/// A change of default route is the clearest "you are on a different network now" signal there is,
/// and `/proc/net/route` shows it without a netlink socket.
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

    #[test]
    fn boottime_is_never_behind_monotonic() {
        // If it were, `saturating_sub` would report zero suspended time forever and resume
        // detection would silently stop working.
        assert!(clock(libc::CLOCK_BOOTTIME) >= clock(libc::CLOCK_MONOTONIC));
    }

    #[test]
    fn a_quiet_machine_reports_no_reason_to_wake() {
        let mut watch = Watch::new();
        assert_eq!(watch.poll(), None);
        assert_eq!(watch.poll(), None);
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

    /// needlecast changes `needle`'s own routes, and a change we made is not news.
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
        assert!(Reason::NetworkChanged.as_str().contains("network"));
    }
}
