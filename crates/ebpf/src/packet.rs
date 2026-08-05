//! Reading and rewriting IPv4 packets from a tc context.
//!
//! Two hazards are handled here that a straightforward implementation gets wrong:
//!
//! **The L2 boundary.** A WireGuard interface is `ARPHRD_NONE` and carries no link header at all,
//! while an Ethernet link carries fourteen bytes before the IP header. Rather than two code paths,
//! the loader reads `/sys/class/net/<iface>/type` and puts the offset in `SleeveConfig`, so one
//! program serves both device classes.
//!
//! **Fragments.** tc ingress runs before IP reassembly, so a UDP datagram larger than the path MTU
//! arrives as several fragments, each hitting this program separately, and only the first carries
//! an L4 header. Later fragments therefore have no port to range-check and no L4 checksum to fix —
//! they are admitted on the address alone, which is sound because the address is what identifies
//! the flow here.

use aya_ebpf::{bindings::TC_ACT_OK, programs::TcContext};
use needlecast_common::{net, tcev, SleeveConfig};

use crate::maps::{tc_bump, SLEEVE_CONFIG};

/// A classifier returns `i32`; the binding is already one on this target.
pub const OK: i32 = TC_ACT_OK;

/// Recompute over a four-byte address change. The L4 checksum covers a pseudo-header containing
/// the addresses, so it changes even though nothing in the L4 header did.
const CSUM_FIELD_LEN: u64 = 4;
const BPF_F_PSEUDO_HDR: u64 = 1 << 4;
/// A zero IPv4 UDP checksum means "not computed" and must stay zero. Without this flag the fixup
/// would turn it into a real value and the receiver would drop the datagram.
const BPF_F_MARK_MANGLED_0: u64 = 1 << 5;

/// What the programs need from an IPv4 header, read once.
pub struct Packet {
    pub l3: usize,
    pub proto: u8,
    pub first_fragment: bool,
    pub l4: usize,
    pub saddr: u32,
    pub daddr: u32,
}

#[inline(always)]
pub fn parse(ctx: &TcContext, prog: u32, l3: usize) -> Option<Packet> {
    let version_ihl: u8 = ctx.load(l3).ok()?;
    let ihl = net::ihl_bytes(version_ihl);
    if ihl < net::IPV4_MIN_HDR {
        tc_bump(prog, tcev::SHORT);
        return None;
    }
    let frag_off: u16 = ctx.load(l3 + net::IPV4_FRAG_OFF).ok()?;
    Some(Packet {
        l3,
        proto: ctx.load(l3 + net::IPV4_PROTO_OFF).ok()?,
        first_fragment: net::is_first_fragment(frag_off),
        // Options make the header variable length, so the L4 header is not reliably 20 bytes in.
        l4: l3 + ihl,
        saddr: ctx.load(l3 + net::IPV4_SADDR_OFF).ok()?,
        daddr: ctx.load(l3 + net::IPV4_DADDR_OFF).ok()?,
    })
}

/// Absolute offset of the L4 checksum, or `None` when there is nothing to fix: either the protocol
/// carries no pseudo-header checksum, or this is not the first fragment so there is no L4 header.
#[inline(always)]
pub fn csum_target(p: &Packet) -> Option<usize> {
    if !p.first_fragment {
        return None;
    }
    net::l4_csum_offset(p.proto).map(|off| p.l4 + off)
}

/// Rewrite one IPv4 address and repair both checksums.
#[inline(always)]
pub fn rewrite_addr(
    ctx: &mut TcContext,
    prog: u32,
    p: &Packet,
    addr_off: usize,
    new_addr: u32,
    l4_csum_off: Option<usize>,
) -> bool {
    let old_addr: u32 = match ctx.load(p.l3 + addr_off) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if old_addr == new_addr {
        return true;
    }
    if ctx.store(p.l3 + addr_off, &new_addr, 0).is_err() {
        tc_bump(prog, tcev::STORE_ERR);
        return false;
    }
    if ctx
        .l3_csum_replace(
            p.l3 + net::IPV4_CSUM_OFF,
            old_addr as u64,
            new_addr as u64,
            CSUM_FIELD_LEN,
        )
        .is_err()
    {
        tc_bump(prog, tcev::CSUM_ERR);
        return false;
    }
    if let Some(off) = l4_csum_off {
        let mut flags = BPF_F_PSEUDO_HDR | CSUM_FIELD_LEN;
        if p.proto == net::IPPROTO_UDP {
            flags |= BPF_F_MARK_MANGLED_0;
        }
        if ctx
            .l4_csum_replace(off, old_addr as u64, new_addr as u64, flags)
            .is_err()
        {
            tc_bump(prog, tcev::CSUM_ERR);
            return false;
        }
    }
    true
}

/// `port_off` is [`net::L4_SPORT_OFF`] or [`net::L4_DPORT_OFF`].
#[inline(always)]
pub fn port_in_range(
    ctx: &TcContext,
    prog: u32,
    p: &Packet,
    cfg: &SleeveConfig,
    port_off: usize,
) -> bool {
    if !p.first_fragment {
        tc_bump(prog, tcev::NOT_FIRST_FRAGMENT);
        return true;
    }
    if net::l4_csum_offset(p.proto).is_none() {
        return true;
    }
    let port_be: u16 = match ctx.load(p.l4 + port_off) {
        Ok(v) => v,
        Err(_) => {
            tc_bump(prog, tcev::SHORT);
            return false;
        }
    };
    if !net::port_in_range(u16::from_be(port_be), cfg.port_lo, cfg.port_hi) {
        tc_bump(prog, tcev::PORT_OUT_OF_RANGE);
        return false;
    }
    true
}

#[inline(always)]
pub fn count_rewrite(prog: u32, proto: u8) {
    match proto {
        net::IPPROTO_TCP => tc_bump(prog, tcev::REWRITTEN_TCP),
        net::IPPROTO_UDP => tc_bump(prog, tcev::REWRITTEN_UDP),
        _ => tc_bump(prog, tcev::REWRITTEN_OTHER),
    }
}

/// Establishes that this is IPv4 and hands off. An Ethernet-framed device says so in the
/// ethertype; an L3-only device has no such header, so the IP version nibble is the only source.
#[inline(always)]
fn is_ipv4(ctx: &TcContext, prog: u32, l3_offset: usize) -> bool {
    let version_byte = if l3_offset >= net::ETH_HDR_LEN {
        let Ok(ethertype) = ctx.load::<u16>(net::ETH_TYPE_OFF) else {
            return false;
        };
        match u16::from_be(ethertype) {
            net::ETH_P_IP => return true,
            net::ETH_P_IPV6 => {
                tc_bump(prog, tcev::V6);
                return false;
            }
            _ => {
                tc_bump(prog, tcev::NOT_IP);
                return false;
            }
        }
    } else {
        let Ok(b) = ctx.load::<u8>(l3_offset) else {
            return false;
        };
        b
    };
    match net::ip_version(version_byte) {
        4 => true,
        6 => {
            tc_bump(prog, tcev::V6);
            false
        }
        _ => {
            tc_bump(prog, tcev::NOT_IP);
            false
        }
    }
}

/// The preamble both tc programs share: count, read the config, bail if disabled, and establish
/// that this is IPv4 at the right offset.
#[inline(always)]
pub fn run(
    ctx: &mut TcContext,
    prog: u32,
    f: fn(&mut TcContext, &SleeveConfig, usize) -> i32,
) -> i32 {
    tc_bump(prog, tcev::TOTAL);
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
