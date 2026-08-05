//! `tc_egress`: put the reply back on the wire with the right source.
//!
//! The server answered from `127.0.0.1`, which is meaningless to the laptop, so the source is
//! rewritten back to the desktop's tunnel address. This is the exact inverse of `tc_ingress` and
//! needs no state to pair them: ports are never translated, so the port pair already identifies the
//! flow.

use aya_ebpf::{macros::classifier, programs::TcContext};
use needlecast_common::{net, tc, tcev, SleeveConfig};

use crate::maps::tc_bump;
use crate::packet::{count_rewrite, csum_target, parse, port_in_range, rewrite_addr, run, OK};

#[inline(always)]
fn egress(ctx: &mut TcContext, cfg: &SleeveConfig, l3: usize) -> i32 {
    let prog = tc::EGRESS;
    let Some(p) = parse(ctx, prog, l3) else {
        return OK;
    };
    if p.saddr != cfg.local_v4 {
        tc_bump(prog, tcev::WRONG_ADDR);
        return OK;
    }
    // The source port here is the one the client addressed on the way in.
    if !port_in_range(ctx, prog, &p, cfg, net::L4_SPORT_OFF) {
        return OK;
    }

    let csum = csum_target(&p);
    if rewrite_addr(ctx, prog, &p, net::IPV4_SADDR_OFF, cfg.transport_v4, csum) {
        count_rewrite(prog, p.proto);
    }
    OK
}

#[classifier]
pub fn tc_egress(mut ctx: TcContext) -> i32 {
    run(&mut ctx, tc::EGRESS, egress)
}
