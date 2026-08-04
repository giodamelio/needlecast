#![no_std]
#![no_main]

mod tc;

use aya_ebpf::{
    bindings::{
        bpf_sock_addr, bpf_sock_tuple, bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 as Tuple4,
        bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2 as Tuple6,
    },
    cty::c_void,
    helpers::{
        bpf_get_netns_cookie, bpf_setsockopt, bpf_sk_lookup_tcp, bpf_sk_lookup_udp, bpf_sk_release,
    },
    macros::{cgroup_sock_addr, map},
    maps::{Array, HashMap},
    programs::SockAddrContext,
    EbpfContext,
};
use needlecast_common::{counter_slot, ev, prog, Config, CONFIG_KEY, COUNTER_SLOTS};

const ALLOW: i32 = 1;

const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;
const SOL_TCP: i32 = 6;
const TCP_SYNCNT: i32 = 7;

#[derive(Clone, Copy, PartialEq)]
enum Proto {
    Tcp,
    Udp,
}

// Pinned so the control CLI can reach them without going through the running loader.
#[map]
static CONFIG: Array<Config> = Array::pinned(1, 0);

#[map]
static COUNTERS: Array<u64> = Array::pinned(COUNTER_SLOTS, 0);

/// Ports the desktop currently serves. Only consulted when `Config::use_listener_map` is set.
#[map]
static DESKTOP_PORTS: HashMap<u16, u8> = HashMap::pinned(8192, 0);

#[inline(always)]
fn bump(prog: u32, ev: u32) {
    if let Some(slot) = COUNTERS.get_ptr_mut(counter_slot(prog, ev)) {
        unsafe { *slot += 1 };
    }
}

#[inline(always)]
unsafe fn port_of(sa: *mut bpf_sock_addr) -> u16 {
    u16::from_be((*sa).user_port as u16)
}

#[inline(always)]
fn is_loopback_v4(addr_be: u32) -> bool {
    u32::from_be(addr_be) >> 24 == 127
}

/// `Some(v4)` when the address is an IPv4-mapped v6 address such as `::ffff:127.0.0.1`, which is
/// what a dual-stack socket sees when `localhost` resolves to v4.
#[inline(always)]
fn mapped_v4(w: &[u32; 4]) -> Option<u32> {
    if w[0] == 0 && w[1] == 0 && u32::from_be(w[2]) == 0xffff {
        Some(w[3])
    } else {
        None
    }
}

#[inline(always)]
fn is_loopback_v6(w: &[u32; 4]) -> bool {
    w[0] == 0 && w[1] == 0 && w[2] == 0 && u32::from_be(w[3]) == 1
}

#[inline(always)]
unsafe fn read_v6(sa: *mut bpf_sock_addr) -> [u32; 4] {
    [
        (*sa).user_ip6[0],
        (*sa).user_ip6[1],
        (*sa).user_ip6[2],
        (*sa).user_ip6[3],
    ]
}

#[inline(always)]
unsafe fn write_v6(sa: *mut bpf_sock_addr, w: [u32; 4]) {
    (*sa).user_ip6[0] = w[0];
    (*sa).user_ip6[1] = w[1];
    (*sa).user_ip6[2] = w[2];
    (*sa).user_ip6[3] = w[3];
}

/// A zeroed source in the tuple means only a listening socket can match, so presence is the
/// answer — an established socket needs a full four-tuple match.
#[inline(always)]
unsafe fn has_local_listener_v4(ctx: *mut c_void, daddr_be: u32, port: u16, proto: Proto) -> bool {
    let mut tuple: bpf_sock_tuple = core::mem::zeroed();
    tuple.__bindgen_anon_1.ipv4 = Tuple4 {
        saddr: 0,
        daddr: daddr_be,
        sport: 0,
        dport: port.to_be(),
    };
    let size = core::mem::size_of::<Tuple4>() as u32;
    let sk = match proto {
        Proto::Tcp => bpf_sk_lookup_tcp(ctx, &mut tuple, size, BPF_F_CURRENT_NETNS, 0),
        Proto::Udp => bpf_sk_lookup_udp(ctx, &mut tuple, size, BPF_F_CURRENT_NETNS, 0),
    };
    if sk.is_null() {
        return false;
    }
    bpf_sk_release(sk as *mut c_void);
    true
}

#[inline(always)]
unsafe fn has_local_listener_v6(
    ctx: *mut c_void,
    daddr: [u32; 4],
    port: u16,
    proto: Proto,
) -> bool {
    let mut tuple: bpf_sock_tuple = core::mem::zeroed();
    tuple.__bindgen_anon_1.ipv6 = Tuple6 {
        saddr: [0; 4],
        daddr,
        sport: 0,
        dport: port.to_be(),
    };
    let size = core::mem::size_of::<Tuple6>() as u32;
    let sk = match proto {
        Proto::Tcp => bpf_sk_lookup_tcp(ctx, &mut tuple, size, BPF_F_CURRENT_NETNS, 0),
        Proto::Udp => bpf_sk_lookup_udp(ctx, &mut tuple, size, BPF_F_CURRENT_NETNS, 0),
    };
    if sk.is_null() {
        return false;
    }
    bpf_sk_release(sk as *mut c_void);
    true
}

/// Everything up to but not including the socket lookup. `None` means decline.
#[inline(always)]
unsafe fn preflight(ctx: &SockAddrContext, prog: u32) -> Option<(Config, u16)> {
    bump(prog, ev::TOTAL);

    let cfg = *CONFIG.get(CONFIG_KEY)?;
    if cfg.enabled == 0 {
        bump(prog, ev::DISABLED);
        return None;
    }

    let cookie = bpf_get_netns_cookie(ctx.as_ptr());
    if cookie == 0 {
        bump(prog, ev::NETNS_COOKIE_UNAVAILABLE);
    } else if cfg.netns_cookie != 0 && cookie != cfg.netns_cookie {
        bump(prog, ev::WRONG_NETNS);
        return None;
    }

    let port = port_of(ctx.sock_addr);
    if port < cfg.port_lo || port > cfg.port_hi {
        bump(prog, ev::PORT_OUT_OF_RANGE);
        return None;
    }

    if cfg.use_listener_map != 0 && DESKTOP_PORTS.get(&port).is_none() {
        bump(prog, ev::NOT_ADVERTISED);
        return None;
    }

    Some((cfg, port))
}

#[inline(always)]
unsafe fn decide_v4(ctx: &SockAddrContext, prog: u32, proto: Proto) -> i32 {
    let sa = ctx.sock_addr;
    let daddr = (*sa).user_ip4;
    if !is_loopback_v4(daddr) {
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

    (*sa).user_ip4 = cfg.target_v4;
    apply_syncnt(ctx, prog, &cfg);
    bump(prog, ev::REWRITTEN);
    ALLOW
}

/// Caps how long a rewritten connection hangs when the desktop has gone away between heartbeats.
/// Only rewritten sockets are touched, so a connection that stayed local keeps the system default.
#[inline(always)]
unsafe fn apply_syncnt(ctx: &SockAddrContext, prog: u32, cfg: &Config) {
    if cfg.syncnt == 0 {
        return;
    }
    let mut value: i32 = cfg.syncnt as i32;
    let rc = bpf_setsockopt(
        ctx.as_ptr(),
        SOL_TCP,
        TCP_SYNCNT,
        &mut value as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    );
    if rc == 0 {
        bump(prog, ev::SETSOCKOPT_OK);
    } else {
        bump(prog, ev::SETSOCKOPT_ERR);
    }
}

#[inline(always)]
unsafe fn decide_v6(ctx: &SockAddrContext, prog: u32, proto: Proto) -> i32 {
    let sa = ctx.sock_addr;
    let daddr = read_v6(sa);

    let mapped = mapped_v4(&daddr);
    let loopback = match mapped {
        Some(v4) => is_loopback_v4(v4),
        None => is_loopback_v6(&daddr),
    };
    if !loopback {
        bump(prog, ev::TOTAL);
        bump(prog, ev::NOT_LOOPBACK);
        return ALLOW;
    }

    let Some((cfg, port)) = preflight(ctx, prog) else {
        return ALLOW;
    };

    // A mapped destination is answered by the v4 stack, so it needs the v4 socket lookup and the
    // v4 target, with the mapping prefix preserved.
    if let Some(v4) = mapped {
        if has_local_listener_v4(ctx.as_ptr(), v4, port, proto) {
            bump(prog, ev::LOCAL_LISTENER);
            return ALLOW;
        }
        write_v6(sa, [daddr[0], daddr[1], daddr[2], cfg.target_v4]);
        bump(prog, ev::REWRITTEN);
        return ALLOW;
    }

    if has_local_listener_v6(ctx.as_ptr(), daddr, port, proto) {
        bump(prog, ev::LOCAL_LISTENER);
        return ALLOW;
    }

    write_v6(sa, cfg.target_v6);
    bump(prog, ev::REWRITTEN);
    ALLOW
}

/// Undo the rewrite so `getpeername()` and `recvmsg()` report what the caller asked for. The port
/// is never translated, so restoring the address is enough and needs no per-connection state.
#[inline(always)]
unsafe fn restore_v4(ctx: &SockAddrContext, prog: u32) -> i32 {
    bump(prog, ev::TOTAL);
    let sa = ctx.sock_addr;
    let Some(cfg) = CONFIG.get(CONFIG_KEY) else {
        return ALLOW;
    };
    if cfg.enabled == 0 {
        bump(prog, ev::DISABLED);
        return ALLOW;
    }
    if (*sa).user_ip4 != cfg.target_v4 {
        return ALLOW;
    }
    let port = port_of(sa);
    if port < cfg.port_lo || port > cfg.port_hi {
        bump(prog, ev::PORT_OUT_OF_RANGE);
        return ALLOW;
    }
    (*sa).user_ip4 = 0x7f000001u32.to_be();
    bump(prog, ev::RESTORED);
    ALLOW
}

#[inline(always)]
unsafe fn restore_v6(ctx: &SockAddrContext, prog: u32) -> i32 {
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
    if port < cfg.port_lo || port > cfg.port_hi {
        bump(prog, ev::PORT_OUT_OF_RANGE);
        return ALLOW;
    }

    if let Some(v4) = mapped_v4(&addr) {
        if v4 == cfg.target_v4 {
            write_v6(sa, [addr[0], addr[1], addr[2], 0x7f000001u32.to_be()]);
            bump(prog, ev::RESTORED);
        }
        return ALLOW;
    }

    if addr == cfg.target_v6 {
        write_v6(sa, [0, 0, 0, 1u32.to_be()]);
        bump(prog, ev::RESTORED);
    }
    ALLOW
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    unsafe { decide_v4(&ctx, prog::CONNECT4, Proto::Tcp) }
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    unsafe { decide_v6(&ctx, prog::CONNECT6, Proto::Tcp) }
}

#[cgroup_sock_addr(getpeername4)]
pub fn getpeername4(ctx: SockAddrContext) -> i32 {
    unsafe { restore_v4(&ctx, prog::GETPEERNAME4) }
}

#[cgroup_sock_addr(getpeername6)]
pub fn getpeername6(ctx: SockAddrContext) -> i32 {
    unsafe { restore_v6(&ctx, prog::GETPEERNAME6) }
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    unsafe { decide_v4(&ctx, prog::SENDMSG4, Proto::Udp) }
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    unsafe { decide_v6(&ctx, prog::SENDMSG6, Proto::Udp) }
}

#[cgroup_sock_addr(recvmsg4)]
pub fn recvmsg4(ctx: SockAddrContext) -> i32 {
    unsafe { restore_v4(&ctx, prog::RECVMSG4) }
}

#[cgroup_sock_addr(recvmsg6)]
pub fn recvmsg6(ctx: SockAddrContext) -> i32 {
    unsafe { restore_v6(&ctx, prog::RECVMSG6) }
}

/// Kept as its own program so a verifier rejection of `bpf_setsockopt` in `cgroup_sock_addr` is an
/// observable result rather than something that takes the whole object down with it.
#[cgroup_sock_addr(connect4)]
pub fn connect4_syncnt_probe(ctx: SockAddrContext) -> i32 {
    unsafe {
        let mut value: i32 = 2;
        let rc = bpf_setsockopt(
            ctx.as_ptr(),
            SOL_TCP,
            TCP_SYNCNT,
            &mut value as *mut i32 as *mut c_void,
            core::mem::size_of::<i32>() as i32,
        );
        if rc == 0 {
            bump(prog::CONNECT4, ev::SETSOCKOPT_OK);
        } else {
            bump(prog::CONNECT4, ev::SETSOCKOPT_ERR);
        }
    }
    ALLOW
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
