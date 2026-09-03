// The test harness needs std, and `net` is the part of this crate most worth testing.
#![cfg_attr(not(test), no_std)]

#[cfg(all(feature = "user", not(test)))]
extern crate std;

pub mod net;

#[cfg(feature = "user")]
pub mod proto;

/// Shared with BPF: the layout must stay stable and `Pod`-safe.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    /// Captured at load time; the decision programs bail when it does not match.
    pub netns_cookie: u64,
    /// Network byte order, as everything the programs compare against is.
    pub target_v4: u32,
    pub target_v6: [u32; 4],
    pub port_lo: u16,
    pub port_hi: u16,
    pub enabled: u8,
    /// Consult `DESKTOP_PORTS` before rewriting.
    pub use_listener_map: u8,
    /// Zero leaves the system default.
    pub syncnt: u8,
    pub _pad: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}

pub const CONFIG_KEY: u32 = 0;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prog {
    Connect4 = 0,
    Connect6 = 1,
    Getpeername4 = 2,
    Getpeername6 = 3,
    Sendmsg4 = 4,
    Sendmsg6 = 5,
    Recvmsg4 = 6,
    Recvmsg6 = 7,
}

impl Prog {
    pub const ALL: &'static [Prog] = &[
        Prog::Connect4,
        Prog::Connect6,
        Prog::Getpeername4,
        Prog::Getpeername6,
        Prog::Sendmsg4,
        Prog::Sendmsg6,
        Prog::Recvmsg4,
        Prog::Recvmsg6,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Prog::Connect4 => "connect4",
            Prog::Connect6 => "connect6",
            Prog::Getpeername4 => "getpeername4",
            Prog::Getpeername6 => "getpeername6",
            Prog::Sendmsg4 => "sendmsg4",
            Prog::Sendmsg6 => "sendmsg6",
            Prog::Recvmsg4 => "recvmsg4",
            Prog::Recvmsg6 => "recvmsg6",
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ev {
    Total = 0,
    Disabled = 1,
    WrongNetns = 2,
    NotLoopback = 3,
    PortOutOfRange = 4,
    LocalListener = 5,
    NotAdvertised = 6,
    Rewritten = 7,
    Restored = 8,
    SkLookupErr = 9,
    SetsockoptOk = 10,
    SetsockoptErr = 11,
    NetnsCookieUnavailable = 12,
    /// IPv6 destination with no IPv6 tunnel address, so there is nowhere to send it.
    NoV6Target = 13,
}

impl Ev {
    /// Counters are indexed `prog * STRIDE + ev`, so this is deliberately larger than `ALL.len()`:
    /// a new event appended below must not shift every existing program's slots.
    pub const STRIDE: u32 = 16;

    pub const ALL: &'static [Ev] = &[
        Ev::Total,
        Ev::Disabled,
        Ev::WrongNetns,
        Ev::NotLoopback,
        Ev::PortOutOfRange,
        Ev::LocalListener,
        Ev::NotAdvertised,
        Ev::Rewritten,
        Ev::Restored,
        Ev::SkLookupErr,
        Ev::SetsockoptOk,
        Ev::SetsockoptErr,
        Ev::NetnsCookieUnavailable,
        Ev::NoV6Target,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Ev::Total => "total",
            Ev::Disabled => "disabled",
            Ev::WrongNetns => "wrong_netns",
            Ev::NotLoopback => "not_loopback",
            Ev::PortOutOfRange => "port_out_of_range",
            Ev::LocalListener => "local_listener",
            Ev::NotAdvertised => "not_advertised",
            Ev::Rewritten => "rewritten",
            Ev::Restored => "restored",
            Ev::SkLookupErr => "sk_lookup_err",
            Ev::SetsockoptOk => "setsockopt_ok",
            Ev::SetsockoptErr => "setsockopt_err",
            Ev::NetnsCookieUnavailable => "netns_cookie_unavailable",
            Ev::NoV6Target => "no_v6_target",
        }
    }
}

pub const COUNTER_SLOTS: u32 = Prog::ALL.len() as u32 * Ev::STRIDE;

pub const fn counter_slot(prog: Prog, ev: Ev) -> u32 {
    prog as u32 * Ev::STRIDE + ev as u32
}

/// Server-side configuration, shared with the tc programs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SleeveConfig {
    pub transport_v4: u32,
    pub transport_peer_v4: u32,
    /// Where inbound packets are delivered, and what the peer is reported as.
    pub local_v4: u32,
    /// All-zero means the v6 datapath is off, and the tc programs pass IPv6 through.
    pub transport_v6: [u32; 4],
    pub transport_peer_v6: [u32; 4],
    pub local_v6: [u32; 4],
    /// Where an inbound v6 packet is redirected. `ip6_rcv_core` drops a loopback destination on any
    /// device that is not itself loopback, so unlike v4 there is nowhere else to deliver it.
    pub lo_ifindex: u32,
    pub port_lo: u16,
    pub port_hi: u16,
    /// 14 on an Ethernet-framed device, 0 on an L3-only one.
    pub l3_offset: u16,
    pub enabled: u8,
    /// Zero ends v6 ingress with `TC_ACT_OK` instead of handing the packet to `lo`. The product
    /// always sets it; the harness can clear it, so the suite measures that the redirect is what
    /// makes v6 delivery work rather than assuming it.
    pub v6_redirect: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SleeveConfig {}

/// What the listener feed needs to decide whether a socket event is worth waking userspace for.
///
/// The offsets locate `oldstate`, `newstate` and `sport` inside a `sock/inet_sock_set_state`
/// record. They are read from the tracepoint's own `format` file at load time rather than written
/// here: the layout has been stable for years but is not ABI, and a wrong offset would quietly
/// stop the feed rather than fail loudly.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FeedConfig {
    pub oldstate_off: u32,
    pub newstate_off: u32,
    pub sport_off: u32,
    pub port_lo: u16,
    pub port_hi: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FeedConfig {}

/// `TCP_LISTEN`, from `include/net/tcp_states.h`. The one transition the feed cares about.
pub const TCP_LISTEN: i32 = 10;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcProg {
    Ingress = 0,
    Egress = 1,
    Getpeername = 2,
    Getpeername6 = 3,
    /// Not a datapath program, but it shares the counter map so `status` reports it beside the
    /// rest — and so "the feed is silent while nothing changes" is assertable.
    Feed = 4,
}

impl TcProg {
    pub const ALL: &'static [TcProg] = &[
        TcProg::Ingress,
        TcProg::Egress,
        TcProg::Getpeername,
        TcProg::Getpeername6,
        TcProg::Feed,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            TcProg::Ingress => "tc_ingress",
            TcProg::Egress => "tc_egress",
            TcProg::Getpeername => "sleeve_getpeername4",
            TcProg::Getpeername6 => "sleeve_getpeername6",
            TcProg::Feed => "listener_feed",
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcEv {
    Total = 0,
    NotIp = 1,
    Short = 2,
    WrongAddr = 3,
    PortOutOfRange = 4,
    NotFirstFragment = 5,
    RewrittenTcp = 6,
    RewrittenUdp = 7,
    RewrittenOther = 8,
    CsumErr = 9,
    StoreErr = 10,
    /// IPv6 seen while no v6 target is configured, so it was passed through untouched.
    V6 = 11,
    /// An extension header chain this parser does not walk.
    V6ExtHdr = 12,
    /// `bpf_skb_change_head` or `bpf_redirect` refused; the packet is dropped rather than delivered
    /// somewhere it was never addressed.
    RedirectErr = 13,
    NoSk = 14,
    Redirected = 15,
}

impl TcEv {
    /// See [`Ev::STRIDE`]. `NoSk`'s discriminant is why this cannot be `ALL.len()`.
    pub const STRIDE: u32 = 16;

    pub const ALL: &'static [TcEv] = &[
        TcEv::Total,
        TcEv::NotIp,
        TcEv::Short,
        TcEv::WrongAddr,
        TcEv::PortOutOfRange,
        TcEv::NotFirstFragment,
        TcEv::RewrittenTcp,
        TcEv::RewrittenUdp,
        TcEv::RewrittenOther,
        TcEv::CsumErr,
        TcEv::StoreErr,
        TcEv::V6,
        TcEv::V6ExtHdr,
        TcEv::RedirectErr,
        TcEv::NoSk,
        TcEv::Redirected,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            TcEv::Total => "total",
            TcEv::NotIp => "not_ip",
            TcEv::Short => "short",
            TcEv::WrongAddr => "wrong_addr",
            TcEv::PortOutOfRange => "port_out_of_range",
            TcEv::NotFirstFragment => "not_first_fragment",
            TcEv::RewrittenTcp => "rewritten_tcp",
            TcEv::RewrittenUdp => "rewritten_udp",
            TcEv::RewrittenOther => "rewritten_other",
            TcEv::CsumErr => "csum_err",
            TcEv::StoreErr => "store_err",
            TcEv::V6 => "v6",
            TcEv::V6ExtHdr => "v6_ext_hdr",
            TcEv::RedirectErr => "redirect_err",
            TcEv::NoSk => "no_sk",
            TcEv::Redirected => "redirected",
        }
    }
}

pub const TC_COUNTER_SLOTS: u32 = TcProg::ALL.len() as u32 * TcEv::STRIDE;

pub const fn tc_counter_slot(prog: TcProg, ev: TcEv) -> u32 {
    prog as u32 * TcEv::STRIDE + ev as u32
}

/// Every counter a client-side dump should walk, paired with its slot.
pub fn all_counters() -> impl Iterator<Item = (Prog, Ev, u32)> {
    Prog::ALL
        .iter()
        .flat_map(|p| Ev::ALL.iter().map(move |e| (*p, *e, counter_slot(*p, *e))))
}

pub fn all_tc_counters() -> impl Iterator<Item = (TcProg, TcEv, u32)> {
    TcProg::ALL.iter().flat_map(|p| {
        TcEv::ALL
            .iter()
            .map(move |e| (*p, *e, tc_counter_slot(*p, *e)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// An event discriminant at or past the stride lands in the next program's block, silently
    /// corrupting both counters.
    #[test]
    fn every_event_fits_inside_the_stride() {
        for ev in Ev::ALL {
            assert!((*ev as u32) < Ev::STRIDE, "{ev:?} overflows its block");
        }
        for ev in TcEv::ALL {
            assert!((*ev as u32) < TcEv::STRIDE, "{ev:?} overflows its block");
        }
    }

    #[test]
    fn every_slot_is_distinct_and_within_the_map() {
        let mut seen = BTreeSet::new();
        for p in Prog::ALL {
            for e in Ev::ALL {
                let slot = counter_slot(*p, *e);
                assert!(slot < COUNTER_SLOTS, "{p:?}.{e:?} is past the map");
                assert!(seen.insert(slot), "{p:?}.{e:?} collides at slot {slot}");
            }
        }

        let mut seen = BTreeSet::new();
        for p in TcProg::ALL {
            for e in TcEv::ALL {
                let slot = tc_counter_slot(*p, *e);
                assert!(slot < TC_COUNTER_SLOTS, "{p:?}.{e:?} is past the map");
                assert!(seen.insert(slot), "{p:?}.{e:?} collides at slot {slot}");
            }
        }
    }

    /// `ALL` is hand-written, so a variant added without extending it would silently never appear
    /// in `status` output.
    #[test]
    fn all_lists_are_complete_and_free_of_duplicates() {
        macro_rules! distinct {
            ($all:expr) => {
                assert_eq!(
                    $all.iter()
                        .map(|v| *v as u32)
                        .collect::<BTreeSet<_>>()
                        .len(),
                    $all.len()
                )
            };
        }
        distinct!(Prog::ALL);
        distinct!(Ev::ALL);
        distinct!(TcProg::ALL);
        distinct!(TcEv::ALL);

        assert_eq!(Prog::ALL.last(), Some(&Prog::Recvmsg6));
        assert_eq!(Ev::ALL.last(), Some(&Ev::NoV6Target));
        assert_eq!(TcProg::ALL.last(), Some(&TcProg::Feed));
        assert_eq!(TcEv::ALL.last(), Some(&TcEv::Redirected));
    }

    #[test]
    fn names_are_unique_so_status_output_is_unambiguous() {
        let progs: BTreeSet<_> = Prog::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(progs.len(), Prog::ALL.len());
        let evs: BTreeSet<_> = Ev::ALL.iter().map(|e| e.as_str()).collect();
        assert_eq!(evs.len(), Ev::ALL.len());
        let tc_progs: BTreeSet<_> = TcProg::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(tc_progs.len(), TcProg::ALL.len());
        let tc_evs: BTreeSet<_> = TcEv::ALL.iter().map(|e| e.as_str()).collect();
        assert_eq!(tc_evs.len(), TcEv::ALL.len());

        assert!(!progs.iter().any(|n| n.is_empty() || *n == "-"));
    }
}
