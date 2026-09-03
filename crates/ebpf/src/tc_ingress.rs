//! Deliver an arriving packet to a server bound to `127.0.0.1`.
//!
//! The destination is rewritten and the packet passed on with `TC_ACT_OK`, which needs exactly one
//! setting: `route_localnet` on our own interface. Without it the packet is dropped as martian,
//! surfacing as a hung connect rather than a clean error.
//!
//! `bpf_redirect(lo, BPF_F_INGRESS)` was measured as an alternative and is worse — it moves only
//! the inbound check, while the reply still needs the sysctl on the transport interface anyway.

use aya_ebpf::{macros::classifier, programs::TcContext};
use needlecast_common::{net, SleeveConfig, TcEv, TcProg};

use crate::maps::tc_bump;
use crate::packet::{count_rewrite, csum_target, parse, port_in_range, rewrite_addr, run, OK};

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

#[classifier]
pub fn tc_ingress(mut ctx: TcContext) -> i32 {
    run(&mut ctx, TcProg::Ingress, ingress)
}
