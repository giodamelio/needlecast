//! Report the address the application asked for, not the one it got.
//!
//! Because the port is never translated, restoring the address is enough and needs no
//! per-connection state. The server uses the same mechanism in reverse: what must change is what
//! an application observes, not what the wire carries.

use aya_ebpf::programs::SockAddrContext;
use needlecast_common::{ev, net, CONFIG_KEY};

use crate::maps::{bump, CONFIG};
use crate::sock::{port_of, read_v6, write_v6, ALLOW};

#[inline(always)]
pub unsafe fn restore_v4(ctx: &SockAddrContext, prog: u32) -> i32 {
    bump(prog, ev::TOTAL);
    let sa = ctx.sock_addr;
    let Some(cfg) = CONFIG.get(CONFIG_KEY) else {
        return ALLOW;
    };
    if cfg.enabled == 0 {
        bump(prog, ev::DISABLED);
        return ALLOW;
    }
    // Only an address we put there; every other socket on the machine passes through.
    if (*sa).user_ip4 != cfg.target_v4 {
        return ALLOW;
    }
    let port = port_of(sa);
    if !net::port_in_range(port, cfg.port_lo, cfg.port_hi) {
        bump(prog, ev::PORT_OUT_OF_RANGE);
        return ALLOW;
    }
    (*sa).user_ip4 = net::LOOPBACK_V4;
    bump(prog, ev::RESTORED);
    ALLOW
}

#[inline(always)]
pub unsafe fn restore_v6(ctx: &SockAddrContext, prog: u32) -> i32 {
    bump(prog, ev::TOTAL);
    let sa = ctx.sock_addr;
    let Some(cfg) = CONFIG.get(CONFIG_KEY) else {
        return ALLOW;
    };
    if cfg.enabled == 0 {
        bump(prog, ev::DISABLED);
        return ALLOW;
    }
    let addr = read_v6(sa);
    let port = port_of(sa);
    if !net::port_in_range(port, cfg.port_lo, cfg.port_hi) {
        bump(prog, ev::PORT_OUT_OF_RANGE);
        return ALLOW;
    }

    // Rewritten in its v4 half, so restored the same way.
    if let Some(v4) = net::mapped_v4(&addr) {
        if v4 == cfg.target_v4 {
            write_v6(sa, [addr[0], addr[1], addr[2], net::LOOPBACK_V4]);
            bump(prog, ev::RESTORED);
        }
        return ALLOW;
    }

    // Nothing was rewritten to it, and an all-zero comparison would match the unspecified address.
    if cfg.target_v6 != [0; 4] && addr == cfg.target_v6 {
        write_v6(sa, net::LOOPBACK_V6);
        bump(prog, ev::RESTORED);
    }
    ALLOW
}
