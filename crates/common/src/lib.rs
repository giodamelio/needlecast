#![no_std]

#[cfg(feature = "user")]
extern crate std;

#[cfg(feature = "user")]
pub mod proto;

/// Shared with BPF, so the layout must stay stable and `Pod`-safe.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    /// Host netns cookie captured at load time. `connect4` bails when it does not match.
    pub netns_cookie: u64,
    /// Where to send a connection that has no local listener, network byte order.
    pub target_v4: u32,
    pub target_v6: [u32; 4],
    pub port_lo: u16,
    pub port_hi: u16,
    pub enabled: u8,
    /// Consult `DESKTOP_PORTS` before rewriting.
    pub use_listener_map: u8,
    /// `TCP_SYNCNT` to set on rewritten sockets. Zero leaves it alone.
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
    "-",
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

/// How the desktop delivers a forwarded flow.
pub mod mode {
    /// Rewrite the destination inbound and the source outbound. The server sees the laptop's
    /// tunnel address as its peer.
    pub const RUNG_A: u8 = 0;
    /// Same on the wire, plus a `cgroup/getpeername4` program that reports the peer as
    /// `127.0.0.1` — so the server cannot distinguish the connection from a local one. Symmetric
    /// with what the laptop does to hide its own rewrite from the client.
    pub const RUNG_B: u8 = 1;
}

/// Desktop-side configuration, shared with the tc programs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SleeveConfig {
    /// This machine's address on the transport link, network byte order.
    pub transport_v4: u32,
    /// The laptop's address on the transport link, network byte order.
    pub transport_peer_v4: u32,
    /// Where inbound packets are delivered, and what the peer is reported as. `127.0.0.1`.
    pub local_v4: u32,
    pub transport_v6: [u32; 4],
    pub local_v6: [u32; 4],
    pub port_lo: u16,
    pub port_hi: u16,
    /// Offset of the IP header within the skb: 14 on an Ethernet-framed device, 0 on an L3-only
    /// one such as a WireGuard interface.
    pub l3_offset: u16,
    pub mode: u8,
    pub enabled: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SleeveConfig {}

pub mod tc {
    pub const INGRESS: u32 = 0;
    pub const EGRESS: u32 = 1;
    pub const GETPEERNAME: u32 = 2;
    pub const COUNT: u32 = 3;
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

pub const TC_PROG_NAMES: [&str; tc::COUNT as usize] =
    ["tc_ingress", "tc_egress", "sleeve_getpeername4"];
