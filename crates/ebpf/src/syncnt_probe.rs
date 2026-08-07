//! A capability probe, not part of the datapath.
//!
//! A verifier rejection takes down whatever object it is part of, so keeping this separate makes
//! one an observable result rather than something that stops the other ten programs loading.
//! Worth the same shape for any future probe.

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext, EbpfContext};
use needlecast_common::{ev, prog};

use crate::maps::bump;
use crate::sock::{set_int_sockopt, ALLOW, SOL_TCP, TCP_SYNCNT};

#[cgroup_sock_addr(connect4)]
pub fn connect4_syncnt_probe(ctx: SockAddrContext) -> i32 {
    unsafe {
        if set_int_sockopt(ctx.as_ptr(), SOL_TCP, TCP_SYNCNT, 2) == 0 {
            bump(prog::CONNECT4, ev::SETSOCKOPT_OK);
        } else {
            bump(prog::CONNECT4, ev::SETSOCKOPT_ERR);
        }
    }
    ALLOW
}
