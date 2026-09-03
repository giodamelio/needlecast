//! Reading and rewriting IPv6 packets from a tc context. Three things differ from v4 in ways a
//! shared implementation would get silently wrong:
//!
//! **A loopback destination cannot be delivered by passing the packet on.** `ip6_rcv_core` drops
//! any packet whose source or destination is `::1` unless it arrived on a loopback device, and
//! there is no `route_localnet` equivalent to switch that off. So ingress hands the packet to `lo`
//! instead. See FINDINGS.md.
//!
//! **There is no header checksum**, so only the L4 one needs repair — but its pseudo-header covers
//! a sixteen-byte address, which `bpf_l4_csum_replace` cannot take as a `from`/`to` pair.
//! `bpf_csum_diff` reduces the change to the 32-bit difference the helper does accept.
//!
//! **Fragmentation is an extension header**, not a field in the fixed header, so the L4 header
//! moves eight bytes further in when one is present.

use aya_ebpf::{
    bindings::TC_ACT_SHOT,
    helpers::{bpf_csum_diff, bpf_redirect, bpf_skb_change_head},
    programs::TcContext,
};
use needlecast_common::{net, SleeveConfig, TcEv, TcProg};

use crate::maps::tc_bump;

const BPF_F_INGRESS: u64 = 1;
const BPF_F_PSEUDO_HDR: u64 = 1 << 4;
const BPF_F_MARK_MANGLED_0: u64 = 1 << 5;
/// Without it the helper applies v4's `CHECKSUM_COMPLETE` bookkeeping to a v6 packet.
const BPF_F_IPV6: u64 = 1 << 7;

pub struct Packet6 {
    pub l3: usize,
    /// After any Fragment header, so this is the real L4 protocol.
    pub proto: u8,
    pub first_fragment: bool,
    pub l4: usize,
    pub saddr: [u32; 4],
    pub daddr: [u32; 4],
}

/// `None` for anything this parser will not touch, having counted why.
#[inline(always)]
pub fn parse(ctx: &TcContext, prog: TcProg, l3: usize) -> Option<Packet6> {
    let next: u8 = ctx.load(l3 + net::IPV6_NEXTHDR_OFF).ok()?;
    let saddr: [u32; 4] = ctx.load(l3 + net::IPV6_SADDR_OFF).ok()?;
    let daddr: [u32; 4] = ctx.load(l3 + net::IPV6_DADDR_OFF).ok()?;

    let (proto, first_fragment, l4) = if next == net::IPPROTO_FRAGMENT {
        let frag = l3 + net::IPV6_HDR_LEN;
        let inner: u8 = ctx.load(frag + net::FRAG6_NEXTHDR_OFF).ok()?;
        let off: u16 = ctx.load(frag + net::FRAG6_OFFSET_OFF).ok()?;
        (
            inner,
            net::is_first_fragment_v6(off),
            frag + net::FRAG6_HDR_LEN,
        )
    } else {
        (next, true, l3 + net::IPV6_HDR_LEN)
    };

    // Only the Fragment header is walked. Anything else is a chain this does not follow, and
    // guessing where L4 starts would corrupt the packet.
    if net::l4_csum_offset(proto).is_none() {
        tc_bump(prog, TcEv::V6ExtHdr);
        return None;
    }

    Some(Packet6 {
        l3,
        proto,
        first_fragment,
        l4,
        saddr,
        daddr,
    })
}

/// `None` when there is nothing to fix, which for v6 means only "not the first fragment".
#[inline(always)]
pub fn csum_target(p: &Packet6) -> Option<usize> {
    if !p.first_fragment {
        return None;
    }
    net::l4_csum_offset(p.proto).map(|off| p.l4 + off)
}

#[inline(always)]
pub fn port_in_range(
    ctx: &TcContext,
    prog: TcProg,
    p: &Packet6,
    cfg: &SleeveConfig,
    port_off: usize,
) -> bool {
    if !p.first_fragment {
        tc_bump(prog, TcEv::NotFirstFragment);
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

/// Rewrite one address and repair the L4 checksum. There is no header checksum to repair.
#[inline(always)]
pub fn rewrite_addr(
    ctx: &mut TcContext,
    prog: TcProg,
    p: &Packet6,
    addr_off: usize,
    new_addr: &[u32; 4],
    l4_csum_off: Option<usize>,
) -> bool {
    let mut old: [u32; 4] = match ctx.load(p.l3 + addr_off) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if net::v6_eq(&old, new_addr) {
        return true;
    }
    if ctx.store(p.l3 + addr_off, new_addr, 0).is_err() {
        tc_bump(prog, TcEv::StoreErr);
        return false;
    }
    let Some(off) = l4_csum_off else {
        return true;
    };

    let mut new = *new_addr;
    // SAFETY: both pointers address sixteen bytes of live stack, which is what the helper reads.
    let diff = unsafe {
        bpf_csum_diff(
            old.as_mut_ptr(),
            16,
            new.as_mut_ptr(),
            16,
            0,
        )
    };
    if diff < 0 {
        tc_bump(prog, TcEv::CsumErr);
        return false;
    }

    let mut flags = BPF_F_PSEUDO_HDR | BPF_F_IPV6;
    // A v6 UDP checksum of zero is illegal rather than "not computed", so a result of zero has to
    // become 0xffff instead of being written out.
    if p.proto == net::IPPROTO_UDP {
        flags |= BPF_F_MARK_MANGLED_0;
    }
    // `from` must be zero: that is what selects the precomputed-difference form of the helper.
    if ctx.l4_csum_replace(off, 0, diff as u64, flags).is_err() {
        tc_bump(prog, TcEv::CsumErr);
        return false;
    }
    true
}

/// Hand the packet to `lo`, the only device a `::1` destination may arrive on.
///
/// Returns `TC_ACT_REDIRECT`, or `TC_ACT_SHOT` if the frame could not be prepared — dropping is
/// right there, because the destination has already been rewritten to an address this device may
/// not deliver.
#[inline(always)]
pub fn redirect_to_loopback(ctx: &mut TcContext, prog: TcProg, cfg: &SleeveConfig) -> i32 {
    if (cfg.l3_offset as usize) < net::ETH_HDR_LEN {
        // `__bpf_redirect_common` refuses a frame with no link header, and an L3-only device such
        // as WireGuard has none. The helper zeroes the bytes it makes room for.
        if unsafe { bpf_skb_change_head(ctx.skb.skb, net::ETH_HDR_LEN as u32, 0) } != 0 {
            tc_bump(prog, TcEv::RedirectErr);
            return TC_ACT_SHOT;
        }
    }

    // `eth_type_trans` derives `pkt_type` from the destination MAC, and `lo`'s is all zeroes.
    // A frame off a real NIC still carries that NIC's address, arrives as `PACKET_OTHERHOST`, and
    // is dropped — so the header is overwritten rather than trusted.
    let blank = [0u8; net::ETH_TYPE_OFF];
    if ctx.store(0, &blank, 0).is_err() {
        tc_bump(prog, TcEv::RedirectErr);
        return TC_ACT_SHOT;
    }
    // Zero here would read as an 802.3 length and never reach the IPv6 handler.
    if ctx
        .store(net::ETH_TYPE_OFF, &net::ETH_P_IPV6.to_be(), 0)
        .is_err()
    {
        tc_bump(prog, TcEv::RedirectErr);
        return TC_ACT_SHOT;
    }

    tc_bump(prog, TcEv::Redirected);
    unsafe { bpf_redirect(cfg.lo_ifindex, BPF_F_INGRESS) as i32 }
}
