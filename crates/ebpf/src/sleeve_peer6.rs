//! Tell the server its peer is `::1`.
//!
//! The v6 counterpart of `sleeve_peer`, and the same reasoning: only what the application observes
//! changes, never the packet. `ss` still shows the real tunnel address.
//!
//! `getpeername6` fires for every socket on the machine, so the three gates below matter.

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use needlecast_common::{net, TcEv, TcProg};

use crate::maps::{tc_bump, SLEEVE_CONFIG};
use crate::sock::ALLOW;

#[cgroup_sock_addr(getpeername6)]
pub fn sleeve_getpeername6(ctx: SockAddrContext) -> i32 {
    let prog = TcProg::Getpeername6;
    tc_bump(prog, TcEv::Total);
    let Some(cfg) = SLEEVE_CONFIG.get(0) else {
        return ALLOW;
    };
    if cfg.enabled == 0 || net::v6_is_unspecified(&cfg.transport_v6) {
        return ALLOW;
    }
    unsafe {
        let sa = ctx.sock_addr;
        // 1. The peer is the paired laptop.
        let peer = [
            (*sa).user_ip6[0],
            (*sa).user_ip6[1],
            (*sa).user_ip6[2],
            (*sa).user_ip6[3],
        ];
        if !net::v6_eq(&peer, &cfg.transport_peer_v6) {
            tc_bump(prog, TcEv::WrongAddr);
            return ALLOW;
        }
        let sk = (*sa).__bindgen_anon_1.sk;
        if sk.is_null() {
            tc_bump(prog, TcEv::NoSk);
            return ALLOW;
        }
        // 2. Our own end is loopback, so this really is a delivered forwarded flow.
        let own = [
            (*sk).src_ip6[0],
            (*sk).src_ip6[1],
            (*sk).src_ip6[2],
            (*sk).src_ip6[3],
        ];
        if !net::v6_eq(&own, &cfg.local_v6) {
            tc_bump(prog, TcEv::WrongAddr);
            return ALLOW;
        }
        // 3. On a port needlecast manages.
        let local_port = (*sk).src_port as u16;
        if !net::port_in_range(local_port, cfg.port_lo, cfg.port_hi) {
            tc_bump(prog, TcEv::PortOutOfRange);
            return ALLOW;
        }
        // Not a knob: the same address it is bound to, so an exact `== ::1` test cannot separate
        // this from a genuinely local connection.
        (*sa).user_ip6[0] = cfg.local_v6[0];
        (*sa).user_ip6[1] = cfg.local_v6[1];
        (*sa).user_ip6[2] = cfg.local_v6[2];
        (*sa).user_ip6[3] = cfg.local_v6[3];
    }
    tc_bump(prog, TcEv::RewrittenTcp);
    ALLOW
}
