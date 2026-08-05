//! `tc_ingress`: deliver an arriving packet to a server bound to `127.0.0.1`.
//!
//! The destination is rewritten from the desktop's tunnel address to `127.0.0.1` and the packet is
//! passed on with `TC_ACT_OK`, so the kernel routes it normally from there. That needs exactly one
//! setting — `net.ipv4.conf.<iface>.route_localnet=1` on needlecast's own interface — without which
//! the packet is dropped as martian, which shows up as a hung connect rather than a clean error.
//!
//! Redirecting into `lo` with `bpf_redirect(BPF_F_INGRESS)` was implemented and measured as an
//! alternative, and is worse: it moves only the inbound check to `lo`, while the reply still leaves
//! from `127.0.0.1` via the transport interface and needs the sysctl there anyway. Two interfaces
//! instead of one, and the extra one is not ours.

use aya_ebpf::{macros::classifier, programs::TcContext};
use needlecast_common::{net, tc, tcev, SleeveConfig};

use crate::maps::tc_bump;
use crate::packet::{count_rewrite, csum_target, parse, port_in_range, rewrite_addr, run, OK};

#[inline(always)]
fn ingress(ctx: &mut TcContext, cfg: &SleeveConfig, l3: usize) -> i32 {
    let prog = tc::INGRESS;
    let Some(p) = parse(ctx, prog, l3) else {
        return OK;
    };
    // Addressed to us on the tunnel, or it is not ours to touch. Checked before the port, because
    // a later fragment has no port to check and the address is what identifies the flow.
    if p.daddr != cfg.transport_v4 {
        tc_bump(prog, tcev::WRONG_ADDR);
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
    run(&mut ctx, tc::INGRESS, ingress)
}
