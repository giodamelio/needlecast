//! Does this loopback destination have a local listener, or does it belong to the server?
//!
//! Shared by `connect*` and `sendmsg*`, whose hooks are **disjoint**: a connected UDP socket goes
//! through `connect4` and never reaches `sendmsg4`, so one function serving both cannot
//! double-count.
//!
//! The lookup is live rather than cached, which is what makes local-wins exact — a program binding
//! the port takes it back with no state to invalidate. TCP re-decides only for new connections;
//! unconnected UDP re-decides per datagram, a deliberate difference with a test asserting it.

use aya_ebpf::{helpers::bpf_get_netns_cookie, programs::SockAddrContext, EbpfContext};
use needlecast_common::{ev, net, Config, CONFIG_KEY};

use crate::maps::{bump, CONFIG, DESKTOP_PORTS};
use crate::sock::{
    has_local_listener_v4, has_local_listener_v6, port_of, read_v6, set_int_sockopt, write_v6,
    Proto, ALLOW, SOL_TCP, TCP_SYNCNT,
};

/// Everything before the socket lookup, which is the expensive part. `None` means decline.
#[inline(always)]
unsafe fn preflight(ctx: &SockAddrContext, prog: u32) -> Option<(Config, u16)> {
    bump(prog, ev::TOTAL);

    let cfg = *CONFIG.get(CONFIG_KEY)?;
    if cfg.enabled == 0 {
        bump(prog, ev::DISABLED);
        return None;
    }

    // Attached to the root cgroup, so these also fire for containers — in our cgroup tree but not
    // our netns. Without the guard, a container reaching an unbound port gets rewritten to a
    // tunnel address that does not exist there and sees ENETUNREACH instead of ECONNREFUSED.
    let cookie = bpf_get_netns_cookie(ctx.as_ptr());
    if cookie == 0 {
        bump(prog, ev::NETNS_COOKIE_UNAVAILABLE);
    } else if cfg.netns_cookie != 0 && cookie != cfg.netns_cookie {
        bump(prog, ev::WRONG_NETNS);
        return None;
    }

    let port = port_of(ctx.sock_addr);
    if !net::port_in_range(port, cfg.port_lo, cfg.port_hi) {
        bump(prog, ev::PORT_OUT_OF_RANGE);
        return None;
    }

    // Latency only: the server refuses an unserved port correctly on its own.
    if cfg.use_listener_map != 0 && DESKTOP_PORTS.get(&port).is_none() {
        bump(prog, ev::NOT_ADVERTISED);
        return None;
    }

    Some((cfg, port))
}

/// A few seconds instead of the stock two minutes of SYN retransmits, when the server went away
/// between heartbeats. Only rewritten sockets, so a local connection keeps the system default.
///
/// TCP only: on a UDP socket this fails on every datagram and buries the real `setsockopt_err`.
#[inline(always)]
unsafe fn apply_syncnt(ctx: &SockAddrContext, prog: u32, cfg: &Config, proto: Proto) {
    if cfg.syncnt == 0 || proto != Proto::Tcp {
        return;
    }
    if set_int_sockopt(ctx.as_ptr(), SOL_TCP, TCP_SYNCNT, cfg.syncnt as i32) == 0 {
        bump(prog, ev::SETSOCKOPT_OK);
    } else {
        bump(prog, ev::SETSOCKOPT_ERR);
    }
}

#[inline(always)]
pub unsafe fn decide_v4(ctx: &SockAddrContext, prog: u32, proto: Proto) -> i32 {
    let sa = ctx.sock_addr;
    let daddr = (*sa).user_ip4;
    // First, so a destination that was never ours costs one comparison.
    if !net::is_loopback_v4(daddr) {
        bump(prog, ev::TOTAL);
        bump(prog, ev::NOT_LOOPBACK);
        return ALLOW;
    }

    let Some((cfg, port)) = preflight(ctx, prog) else {
        return ALLOW;
    };

    if has_local_listener_v4(ctx.as_ptr(), daddr, port, proto) {
        bump(prog, ev::LOCAL_LISTENER);
        return ALLOW;
    }

    // The port is never translated, so the reverse programs need no per-connection state.
    (*sa).user_ip4 = cfg.target_v4;
    apply_syncnt(ctx, prog, &cfg, proto);
    bump(prog, ev::REWRITTEN);
    ALLOW
}

#[inline(always)]
pub unsafe fn decide_v6(ctx: &SockAddrContext, prog: u32, proto: Proto) -> i32 {
    let sa = ctx.sock_addr;
    let daddr = read_v6(sa);

    let mapped = net::mapped_v4(&daddr);
    let loopback = match mapped {
        Some(v4) => net::is_loopback_v4(v4),
        None => net::is_loopback_v6(&daddr),
    };
    if !loopback {
        bump(prog, ev::TOTAL);
        bump(prog, ev::NOT_LOOPBACK);
        return ALLOW;
    }

    let Some((cfg, port)) = preflight(ctx, prog) else {
        return ALLOW;
    };

    // Answered by the v4 stack, so it needs the v4 lookup and target with the prefix preserved.
    if let Some(v4) = mapped {
        if has_local_listener_v4(ctx.as_ptr(), v4, port, proto) {
            bump(prog, ev::LOCAL_LISTENER);
            return ALLOW;
        }
        write_v6(sa, [daddr[0], daddr[1], daddr[2], cfg.target_v4]);
        // The same cap as the v4 path. A dual-stack program asking for `localhost` arrives here,
        // not in `decide_v4`, so leaving it out would give exactly those programs the stock
        // two-minute hang.
        apply_syncnt(ctx, prog, &cfg, proto);
        bump(prog, ev::REWRITTEN);
        return ALLOW;
    }

    // Declining is the only safe answer with no v6 target: rewriting to the unspecified address
    // would send the connection nowhere while looking like it worked.
    if cfg.target_v6 == [0; 4] {
        bump(prog, ev::NO_V6_TARGET);
        return ALLOW;
    }

    if has_local_listener_v6(ctx.as_ptr(), daddr, port, proto) {
        bump(prog, ev::LOCAL_LISTENER);
        return ALLOW;
    }

    write_v6(sa, cfg.target_v6);
    apply_syncnt(ctx, prog, &cfg, proto);
    bump(prog, ev::REWRITTEN);
    ALLOW
}
