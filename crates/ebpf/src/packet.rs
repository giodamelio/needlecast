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
use needlecast_common::{net, SleeveConfig, TcEv, TcProg};

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
pub fn parse(ctx: &TcContext, prog: TcProg, l3: usize) -> Option<Packet> {
    let version_ihl: u8 = ctx.load(l3).ok()?;
    let ihl = net::ihl_bytes(version_ihl);
    if ihl < net::IPV4_MIN_HDR {
        tc_bump(prog, TcEv::Short);
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
    prog: TcProg,
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
        tc_bump(prog, TcEv::StoreErr);
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
        tc_bump(prog, TcEv::CsumErr);
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
            tc_bump(prog, TcEv::CsumErr);
            return false;
        }
    }
    true
}

#[inline(always)]
pub fn port_in_range(
    ctx: &TcContext,
    prog: TcProg,
    p: &Packet,
    cfg: &SleeveConfig,
    port_off: usize,
) -> bool {
    if !p.first_fragment {
        tc_bump(prog, TcEv::NotFirstFragment);
        return true;
    }
    if net::l4_csum_offset(p.proto).is_none() {
        return true;
    }
    let port_be: u16 = match ctx.load(p.l4 + port_off) {
        Ok(v) => v,
        Err(_) => {
            tc_bump(prog, TcEv::Short);
            return false;
        }
    };
    if !net::port_in_range(u16::from_be(port_be), cfg.port_lo, cfg.port_hi) {
        tc_bump(prog, TcEv::PortOutOfRange);
        return false;
    }
    true
}

#[inline(always)]
pub fn count_rewrite(prog: TcProg, proto: u8) {
    match proto {
        net::IPPROTO_TCP => tc_bump(prog, TcEv::RewrittenTcp),
        net::IPPROTO_UDP => tc_bump(prog, TcEv::RewrittenUdp),
        _ => tc_bump(prog, TcEv::RewrittenOther),
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum Version {
    V4,
    V6,
}

/// An Ethernet-framed device says so in the ethertype; an L3-only one has no such header, leaving
/// the IP version nibble as the only source.
#[inline(always)]
fn ip_version(ctx: &TcContext, prog: TcProg, l3_offset: usize) -> Option<Version> {
    let version_byte = if l3_offset >= net::ETH_HDR_LEN {
        let ethertype = ctx.load::<u16>(net::ETH_TYPE_OFF).ok()?;
        match u16::from_be(ethertype) {
            net::ETH_P_IP => return Some(Version::V4),
            net::ETH_P_IPV6 => return Some(Version::V6),
            _ => {
                tc_bump(prog, TcEv::NotIp);
                return None;
            }
        }
    } else {
        ctx.load::<u8>(l3_offset).ok()?
    };
    match net::ip_version(version_byte) {
        4 => Some(Version::V4),
        6 => Some(Version::V6),
        _ => {
            tc_bump(prog, TcEv::NotIp);
            None
        }
    }
}

/// The preamble both tc programs share. IPv6 reaches `v6` only once a v6 tunnel address is
/// configured; before that it is counted and passed through, which is what an IPv4-only pairing
/// wants.
#[inline(always)]
pub fn run(
    ctx: &mut TcContext,
    prog: TcProg,
    v4: fn(&mut TcContext, &SleeveConfig, usize) -> i32,
    v6: fn(&mut TcContext, &SleeveConfig, usize) -> i32,
) -> i32 {
    tc_bump(prog, TcEv::Total);
    let Some(cfg) = SLEEVE_CONFIG.get(0) else {
        return OK;
    };
    if cfg.enabled == 0 {
        return OK;
    }
    let l3 = cfg.l3_offset as usize;
    match ip_version(ctx, prog, l3) {
        Some(Version::V4) => v4(ctx, cfg, l3),
        Some(Version::V6) => {
            if net::v6_is_unspecified(&cfg.transport_v6) {
                tc_bump(prog, TcEv::V6);
                return OK;
            }
            v6(ctx, cfg, l3)
        }
        None => OK,
    }
}
