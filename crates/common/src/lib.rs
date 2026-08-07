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

pub mod prog {
    pub const CONNECT4: u32 = 0;
    pub const CONNECT6: u32 = 1;
    pub const GETPEERNAME4: u32 = 2;
    pub const GETPEERNAME6: u32 = 3;
    pub const SENDMSG4: u32 = 4;
    pub const SENDMSG6: u32 = 5;
    pub const RECVMSG4: u32 = 6;
    pub const RECVMSG6: u32 = 7;
    pub const COUNT: u32 = 8;
}

pub mod ev {
    pub const TOTAL: u32 = 0;
    pub const DISABLED: u32 = 1;
    pub const WRONG_NETNS: u32 = 2;
    pub const NOT_LOOPBACK: u32 = 3;
    pub const PORT_OUT_OF_RANGE: u32 = 4;
    pub const LOCAL_LISTENER: u32 = 5;
    pub const NOT_ADVERTISED: u32 = 6;
    pub const REWRITTEN: u32 = 7;
    pub const RESTORED: u32 = 8;
    pub const SK_LOOKUP_ERR: u32 = 9;
    pub const SETSOCKOPT_OK: u32 = 10;
    pub const SETSOCKOPT_ERR: u32 = 11;
    pub const NETNS_COOKIE_UNAVAILABLE: u32 = 12;
    /// IPv6 destination with no IPv6 tunnel address, so there is nowhere to send it.
    pub const NO_V6_TARGET: u32 = 13;
    pub const COUNT: u32 = 16;
}

pub const COUNTER_SLOTS: u32 = prog::COUNT * ev::COUNT;

pub const fn counter_slot(prog: u32, ev: u32) -> u32 {
    prog * ev::COUNT + ev
}

pub const EV_NAMES: [&str; ev::COUNT as usize] = [
    "total",
    "disabled",
    "wrong_netns",
    "not_loopback",
    "port_out_of_range",
    "local_listener",
    "not_advertised",
    "rewritten",
    "restored",
    "sk_lookup_err",
    "setsockopt_ok",
    "setsockopt_err",
    "netns_cookie_unavailable",
    "no_v6_target",
    "-",
    "-",
];

pub const PROG_NAMES: [&str; prog::COUNT as usize] = [
    "connect4",
    "connect6",
    "getpeername4",
    "getpeername6",
    "sendmsg4",
    "sendmsg6",
    "recvmsg4",
    "recvmsg6",
];

/// Server-side configuration, shared with the tc programs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SleeveConfig {
    pub transport_v4: u32,
    pub transport_peer_v4: u32,
    /// Where inbound packets are delivered, and what the peer is reported as.
    pub local_v4: u32,
    /// Unused while the server datapath is IPv4-only, so adding v6 is new code rather than a layout
    /// change to a struct BPF and userspace both depend on.
    pub transport_v6: [u32; 4],
    pub transport_peer_v6: [u32; 4],
    pub local_v6: [u32; 4],
    pub port_lo: u16,
    pub port_hi: u16,
    /// 14 on an Ethernet-framed device, 0 on an L3-only one.
    pub l3_offset: u16,
    pub enabled: u8,
    pub _pad: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SleeveConfig {}

pub mod tc {
    pub const INGRESS: u32 = 0;
    pub const EGRESS: u32 = 1;
    pub const GETPEERNAME: u32 = 2;
    /// Reserved: counters are indexed `prog * tcev::COUNT + ev`, so adding a program later would
    /// reindex every existing one.
    pub const GETPEERNAME6: u32 = 3;
    pub const COUNT: u32 = 4;
}

pub mod tcev {
    pub const TOTAL: u32 = 0;
    pub const NOT_IP: u32 = 1;
    pub const SHORT: u32 = 2;
    pub const WRONG_ADDR: u32 = 3;
    pub const PORT_OUT_OF_RANGE: u32 = 4;
    pub const NOT_FIRST_FRAGMENT: u32 = 5;
    pub const REWRITTEN_TCP: u32 = 6;
    pub const REWRITTEN_UDP: u32 = 7;
    pub const REWRITTEN_OTHER: u32 = 8;
    pub const CSUM_ERR: u32 = 9;
    pub const STORE_ERR: u32 = 10;
    pub const V6: u32 = 11;
    pub const NO_SK: u32 = 14;
    pub const COUNT: u32 = 16;
}

pub const TC_COUNTER_SLOTS: u32 = tc::COUNT * tcev::COUNT;

pub const fn tc_counter_slot(prog: u32, ev: u32) -> u32 {
    prog * tcev::COUNT + ev
}

pub const TCEV_NAMES: [&str; tcev::COUNT as usize] = [
    "total",
    "not_ip",
    "short",
    "wrong_addr",
    "port_out_of_range",
    "not_first_fragment",
    "rewritten_tcp",
    "rewritten_udp",
    "rewritten_other",
    "csum_err",
    "store_err",
    "v6",
    "-",
    "-",
    "no_sk",
    "-",
];

pub const TC_PROG_NAMES: [&str; tc::COUNT as usize] = [
    "tc_ingress",
    "tc_egress",
    "sleeve_getpeername4",
    "sleeve_getpeername6",
];
