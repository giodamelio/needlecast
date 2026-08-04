//! Desktop-side datapath.
//!
//! The wire path is the same either way: rewrite the destination inbound and the source outbound,
//! statelessly, because ports are never translated and the port pair already identifies the flow.
//! Rung B adds a `cgroup/getpeername4` program that reports `127.0.0.1` as the peer, so a server
//! cannot distinguish a forwarded connection from a local one. Nothing on the machine outside the
//! transport interface is touched: no route, nothing attached to `lo`.

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{cgroup_sock_addr, classifier, map},
    maps::Array,
    programs::{SockAddrContext, TcContext},
};
use needlecast_common::{mode, tc, tc_counter_slot, tcev, SleeveConfig, TC_COUNTER_SLOTS};

/// A classifier returns `i32`; the binding is already one on this target.
const OK: i32 = TC_ACT_OK;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

const IPV4_FRAG_OFF: usize = 6;
const IPV4_PROTO_OFF: usize = 9;
const IPV4_CSUM_OFF: usize = 10;
const IPV4_SADDR_OFF: usize = 12;
const IPV4_DADDR_OFF: usize = 16;
const IPV4_MIN_HDR: usize = 20;

const TCP_CSUM_OFF: usize = 16;
const UDP_CSUM_OFF: usize = 6;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

const BPF_F_PSEUDO_HDR: u64 = 1 << 4;
const BPF_F_MARK_MANGLED_0: u64 = 1 << 5;

#[map]
static SLEEVE_CONFIG: Array<SleeveConfig> = Array::pinned(1, 0);

#[map]
static TC_COUNTERS: Array<u64> = Array::pinned(TC_COUNTER_SLOTS, 0);

#[inline(always)]
fn bump(prog: u32, ev: u32) {
    if let Some(slot) = TC_COUNTERS.get_ptr_mut(tc_counter_slot(prog, ev)) {
        unsafe { *slot += 1 };
    }
}

/// True for the first fragment or an unfragmented packet. Later fragments carry no L4 header, so
/// they have neither a port to test nor an L4 checksum to fix.
#[inline(always)]
fn is_first_fragment(frag_off_be: u16) -> bool {
    u16::from_be(frag_off_be) & 0x1fff == 0
}

/// Rewrite one IPv4 address and repair both checksums. The L4 checksum covers the pseudo-header, so
/// it changes even though nothing in the L4 header did.
#[inline(always)]
fn rewrite_addr(
    ctx: &mut TcContext,
    prog: u32,
    l3: usize,
    addr_off: usize,
    new_addr: u32,
    proto: u8,
    l4_csum_off: Option<usize>,
) -> bool {
    let old_addr: u32 = match ctx.load(l3 + addr_off) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if old_addr == new_addr {
        return true;
    }
    if ctx.store(l3 + addr_off, &new_addr, 0).is_err() {
        bump(prog, tcev::STORE_ERR);
        return false;
    }
    if ctx
        .l3_csum_replace(l3 + IPV4_CSUM_OFF, old_addr as u64, new_addr as u64, 4)
        .is_err()
    {
        bump(prog, tcev::CSUM_ERR);
        return false;
    }
    if let Some(off) = l4_csum_off {
        // A zero IPv4 UDP checksum means "not computed" and must stay zero, which is what
        // BPF_F_MARK_MANGLED_0 preserves.
        let mut flags = BPF_F_PSEUDO_HDR | 4;
        if proto == IPPROTO_UDP {
            flags |= BPF_F_MARK_MANGLED_0;
        }
        if ctx
            .l4_csum_replace(off, old_addr as u64, new_addr as u64, flags)
            .is_err()
        {
            bump(prog, tcev::CSUM_ERR);
            return false;
        }
    }
    true
}

struct Packet {
    l3: usize,
    proto: u8,
    first_fragment: bool,
    l4: usize,
    saddr: u32,
    daddr: u32,
}

#[inline(always)]
fn parse(ctx: &TcContext, prog: u32, l3: usize) -> Option<Packet> {
    let ihl_byte: u8 = ctx.load(l3).ok()?;
    let ihl = ((ihl_byte & 0x0f) as usize) * 4;
    if ihl < IPV4_MIN_HDR {
        bump(prog, tcev::SHORT);
        return None;
    }
    let frag_off: u16 = ctx.load(l3 + IPV4_FRAG_OFF).ok()?;
    Some(Packet {
        l3,
        proto: ctx.load(l3 + IPV4_PROTO_OFF).ok()?,
        first_fragment: is_first_fragment(frag_off),
        l4: l3 + ihl,
        saddr: ctx.load(l3 + IPV4_SADDR_OFF).ok()?,
        daddr: ctx.load(l3 + IPV4_DADDR_OFF).ok()?,
    })
}

#[inline(always)]
fn l4_csum_off(p: &Packet) -> Option<usize> {
    match p.proto {
        IPPROTO_TCP => Some(p.l4 + TCP_CSUM_OFF),
        IPPROTO_UDP => Some(p.l4 + UDP_CSUM_OFF),
        _ => None,
    }
}

/// Only fix the L4 checksum on the first fragment; later ones have no L4 header to fix.
#[inline(always)]
fn csum_target(p: &Packet) -> Option<usize> {
    if p.first_fragment {
        l4_csum_off(p)
    } else {
        None
    }
}

/// `port_off` is 0 for the source port and 2 for the destination port. Later fragments have no
/// ports at all, so they are admitted on the address match alone — the address is what identifies
/// the flow here, and it has already matched.
#[inline(always)]
fn port_in_range(
    ctx: &TcContext,
    prog: u32,
    p: &Packet,
    cfg: &SleeveConfig,
    port_off: usize,
) -> bool {
    if !p.first_fragment {
        bump(prog, tcev::NOT_FIRST_FRAGMENT);
        return true;
    }
    if l4_csum_off(p).is_none() {
        return true;
    }
    let port_be: u16 = match ctx.load(p.l4 + port_off) {
        Ok(v) => v,
        Err(_) => {
            bump(prog, tcev::SHORT);
            return false;
        }
    };
    let port = u16::from_be(port_be);
    if port < cfg.port_lo || port > cfg.port_hi {
        bump(prog, tcev::PORT_OUT_OF_RANGE);
        return false;
    }
    true
}

#[inline(always)]
fn count_rewrite(prog: u32, proto: u8) {
    match proto {
        IPPROTO_TCP => bump(prog, tcev::REWRITTEN_TCP),
        IPPROTO_UDP => bump(prog, tcev::REWRITTEN_UDP),
        _ => bump(prog, tcev::REWRITTEN_OTHER),
    }
}

#[inline(always)]
fn ingress(ctx: &mut TcContext, cfg: &SleeveConfig, l3: usize) -> i32 {
    let prog = tc::INGRESS;
    let Some(p) = parse(ctx, prog, l3) else {
        return OK;
    };
    if p.daddr != cfg.transport_v4 {
        bump(prog, tcev::WRONG_ADDR);
        return OK;
    }
    if !port_in_range(ctx, prog, &p, cfg, 2) {
        return OK;
    }

    let csum = csum_target(&p);
    let ok = rewrite_addr(ctx, prog, p.l3, IPV4_DADDR_OFF, cfg.local_v4, p.proto, csum);
    if ok {
        count_rewrite(prog, p.proto);
    }
    OK
}

/// Runs on the transport interface. In `RUNG_B_LO` the reply never reaches here by routing — it
/// arrives already rewritten via `bpf_redirect`, so the source match simply fails and it passes.
#[inline(always)]
fn egress(ctx: &mut TcContext, cfg: &SleeveConfig, l3: usize) -> i32 {
    let prog = tc::EGRESS;
    let Some(p) = parse(ctx, prog, l3) else {
        return OK;
    };
    if p.saddr != cfg.local_v4 {
        bump(prog, tcev::WRONG_ADDR);
        return OK;
    }
    if !port_in_range(ctx, prog, &p, cfg, 0) {
        return OK;
    }

    let csum = csum_target(&p);
    if rewrite_addr(
        ctx,
        prog,
        p.l3,
        IPV4_SADDR_OFF,
        cfg.transport_v4,
        p.proto,
        csum,
    ) {
        count_rewrite(prog, p.proto);
    }
    OK
}

/// Establishes that this is IPv4 and hands off. On an Ethernet-framed device the ethertype says
/// whether it is IP at all; an L3-only device has no such header.
#[inline(always)]
fn is_ipv4(ctx: &TcContext, prog: u32, l3_offset: usize) -> bool {
    if l3_offset >= 14 {
        let Ok(ethertype) = ctx.load::<u16>(12) else {
            return false;
        };
        match u16::from_be(ethertype) {
            ETH_P_IP => true,
            ETH_P_IPV6 => {
                bump(prog, tcev::V6);
                false
            }
            _ => {
                bump(prog, tcev::NOT_IP);
                false
            }
        }
    } else {
        let Ok(version_byte) = ctx.load::<u8>(l3_offset) else {
            return false;
        };
        match version_byte >> 4 {
            4 => true,
            6 => {
                bump(prog, tcev::V6);
                false
            }
            _ => {
                bump(prog, tcev::NOT_IP);
                false
            }
        }
    }
}

#[inline(always)]
fn run(ctx: &mut TcContext, prog: u32, f: fn(&mut TcContext, &SleeveConfig, usize) -> i32) -> i32 {
    bump(prog, tcev::TOTAL);
    let Some(cfg) = SLEEVE_CONFIG.get(0) else {
        return OK;
    };
    if cfg.enabled == 0 {
        return OK;
    }
    let l3 = cfg.l3_offset as usize;
    if !is_ipv4(ctx, prog, l3) {
        return OK;
    }
    f(ctx, cfg, l3)
}

#[classifier]
pub fn tc_ingress(mut ctx: TcContext) -> i32 {
    run(&mut ctx, tc::INGRESS, ingress)
}

#[classifier]
pub fn tc_egress(mut ctx: TcContext) -> i32 {
    run(&mut ctx, tc::EGRESS, egress)
}

/// `RUNG_B`. The packet keeps the laptop's tunnel address as its source, so routing
/// works with no help, and this rewrites only what the server is told when it calls `accept()` or
/// `getpeername()`. Gated on the socket's own local address and port so it cannot touch anything
/// but a forwarded connection.
#[cgroup_sock_addr(getpeername4)]
pub fn sleeve_getpeername4(ctx: SockAddrContext) -> i32 {
    let prog = tc::GETPEERNAME;
    bump(prog, tcev::TOTAL);
    let Some(cfg) = SLEEVE_CONFIG.get(0) else {
        return 1;
    };
    if cfg.enabled == 0 || cfg.mode != mode::RUNG_B {
        return 1;
    }
    unsafe {
        let sa = ctx.sock_addr;
        if (*sa).user_ip4 != cfg.transport_peer_v4 {
            bump(prog, tcev::WRONG_ADDR);
            return 1;
        }
        let sk = (*sa).__bindgen_anon_1.sk;
        if sk.is_null() {
            bump(prog, tcev::NO_SK);
            return 1;
        }
        if (*sk).src_ip4 != cfg.local_v4 {
            bump(prog, tcev::WRONG_ADDR);
            return 1;
        }
        let local_port = (*sk).src_port as u16;
        if local_port < cfg.port_lo || local_port > cfg.port_hi {
            bump(prog, tcev::PORT_OUT_OF_RANGE);
            return 1;
        }
        // The same address the server is bound to, so what it is told is byte-identical to a
        // genuinely local connection. There is deliberately nothing here to configure.
        (*sa).user_ip4 = cfg.local_v4;
    }
    bump(prog, tcev::REWRITTEN_TCP);
    1
}
