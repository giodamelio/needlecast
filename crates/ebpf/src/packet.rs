//! Reading and rewriting IPv4 packets from a tc context. Two hazards a straightforward
//! implementation gets wrong:
//!
//! **The L2 boundary.** WireGuard is `ARPHRD_NONE` with no link header; Ethernet has fourteen
//! bytes before the IP header. The loader reads the device type and puts the offset in
//! `SleeveConfig`, so one program serves both.
//!
//! **Fragments.** Only the first carries an L4 header, so later ones have no port to check and no
//! L4 checksum to fix. They are admitted on the address alone, which identifies the flow here.

use aya_ebpf::{bindings::TC_ACT_OK, programs::TcContext};
use needlecast_common::{net, tcev, SleeveConfig};

use crate::maps::{tc_bump, SLEEVE_CONFIG};

pub const OK: i32 = TC_ACT_OK;

/// The L4 checksum covers a pseudo-header containing the addresses, so it changes even though
/// nothing in the L4 header did.
const CSUM_FIELD_LEN: u64 = 4;
const BPF_F_PSEUDO_HDR: u64 = 1 << 4;
/// A zero IPv4 UDP checksum means "not computed" and must stay zero, or the receiver drops it.
const BPF_F_MARK_MANGLED_0: u64 = 1 << 5;

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
        l4: l3 + ihl,
        saddr: ctx.load(l3 + net::IPV4_SADDR_OFF).ok()?,
        daddr: ctx.load(l3 + net::IPV4_DADDR_OFF).ok()?,
    })
}

/// `None` when there is nothing to fix: no pseudo-header checksum, or not the first fragment.
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

/// An Ethernet-framed device says so in the ethertype; an L3-only one has no such header, leaving
/// the IP version nibble as the only source.
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

/// The preamble both tc programs share.
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
