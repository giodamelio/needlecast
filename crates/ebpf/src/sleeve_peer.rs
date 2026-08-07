//! Tell the server its peer is `127.0.0.1`.
//!
//! Rewriting the source on the wire instead fails the requirement: the reply is then addressed into
//! `127.0.0.0/8`, which the kernel's own `local` route swallows, and getting it out needs a change
//! to a machine needlecast does not own. It also forces a *distinct* address such as `127.71.0.1`,
//! which is the "almost but not quite local" outcome to avoid.
//!
//! So the packet is left alone and only what the application observes changes. `ss` still shows the
//! real tunnel address, which is a feature: the operator sees the truth, the application does not.
//!
//! `getpeername4` fires for every socket on the machine, so the three gates below matter.

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use needlecast_common::{net, tc, tcev};

use crate::maps::{tc_bump, SLEEVE_CONFIG};
use crate::sock::ALLOW;

#[cgroup_sock_addr(getpeername4)]
pub fn sleeve_getpeername4(ctx: SockAddrContext) -> i32 {
    let prog = tc::GETPEERNAME;
    tc_bump(prog, tcev::TOTAL);
    let Some(cfg) = SLEEVE_CONFIG.get(0) else {
        return ALLOW;
    };
    if cfg.enabled == 0 {
        return ALLOW;
    }
    unsafe {
        let sa = ctx.sock_addr;
        // 1. The peer is the paired laptop.
        if (*sa).user_ip4 != cfg.transport_peer_v4 {
            tc_bump(prog, tcev::WRONG_ADDR);
            return ALLOW;
        }
        let sk = (*sa).__bindgen_anon_1.sk;
        if sk.is_null() {
            tc_bump(prog, tcev::NO_SK);
            return ALLOW;
        }
        // 2. Our own end is loopback, so this really is a delivered forwarded flow.
        if (*sk).src_ip4 != cfg.local_v4 {
            tc_bump(prog, tcev::WRONG_ADDR);
            return ALLOW;
        }
        // 3. On a port needlecast manages.
        let local_port = (*sk).src_port as u16;
        if !net::port_in_range(local_port, cfg.port_lo, cfg.port_hi) {
            tc_bump(prog, tcev::PORT_OUT_OF_RANGE);
            return ALLOW;
        }
        // Not a knob: the same address it is bound to, so an exact `== 127.0.0.1` test cannot
        // separate this from a genuinely local connection.
        (*sa).user_ip4 = cfg.local_v4;
    }
    tc_bump(prog, tcev::REWRITTEN_TCP);
    ALLOW
}
