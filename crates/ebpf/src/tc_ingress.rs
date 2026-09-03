//! Deliver an arriving packet to a server bound to loopback.
//!
//! The two families need different endings for the same rewrite:
//!
//! - **IPv4** is passed on with `TC_ACT_OK`, which needs exactly one setting: `route_localnet` on
//!   our own interface. Without it the packet is dropped as martian, surfacing as a hung connect
//!   rather than a clean error. `bpf_redirect` was measured as an alternative and is worse here —
//!   it moves only the inbound check, while the reply still needs the sysctl anyway.
//! - **IPv6** has no such setting to turn off, so the packet is handed to `lo` instead. That costs
//!   no sysctl at all, because the only check is on input.

use aya_ebpf::{macros::classifier, programs::TcContext};
use needlecast_common::{net, SleeveConfig, TcEv, TcProg};

use crate::maps::tc_bump;
use crate::packet::{count_rewrite, csum_target, parse, port_in_range, rewrite_addr, run, OK};
use crate::packet6;

#[inline(always)]
fn ingress(ctx: &mut TcContext, cfg: &SleeveConfig, l3: usize) -> i32 {
    let prog = TcProg::Ingress;
    let Some(p) = parse(ctx, prog, l3) else {
        return OK;
    };
    // Before the port, because a later fragment has no port and the address identifies the flow.
    if p.daddr != cfg.transport_v4 {
        tc_bump(prog, TcEv::WrongAddr);
        return OK;
    }
    if !port_in_range(ctx, prog, &p, cfg, net::L4_DPORT_OFF) {
        return OK;
    }

    let csum = csum_target(&p);
    if rewrite_addr(ctx, prog, &p, net::IPV4_DADDR_OFF, cfg.local_v4, csum) {
        count_rewrite(prog, p.proto);
    }
    OK
}

#[inline(always)]
fn ingress6(ctx: &mut TcContext, cfg: &SleeveConfig, l3: usize) -> i32 {
    let prog = TcProg::Ingress;
    let Some(p) = packet6::parse(ctx, prog, l3) else {
        return OK;
    };
    if !net::v6_eq(&p.daddr, &cfg.transport_v6) {
        tc_bump(prog, TcEv::WrongAddr);
        return OK;
    }
    if !packet6::port_in_range(ctx, prog, &p, cfg, net::L4_DPORT_OFF) {
        return OK;
    }

    let csum = packet6::csum_target(&p);
    let proto = p.proto;
    if !packet6::rewrite_addr(ctx, prog, &p, net::IPV6_DADDR_OFF, &cfg.local_v6, csum) {
        return OK;
    }
    count_rewrite(prog, proto);
    if cfg.v6_redirect == 0 {
        return OK;
    }
    // Only after the rewrite succeeded: redirecting an unmodified packet into `lo` would deliver
    // it to the wrong stack entirely.
    packet6::redirect_to_loopback(ctx, prog, cfg)
}

#[classifier]
pub fn tc_ingress(mut ctx: TcContext) -> i32 {
    run(&mut ctx, TcProg::Ingress, ingress, ingress6)
}
