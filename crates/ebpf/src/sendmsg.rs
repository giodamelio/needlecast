//! The same decision for UDP sockets that never called `connect()`.
//!
//! No stored destination means this re-decides per datagram, so a local listener appearing mid-flow
//! redirects the next one. Deliberate: for a connectionless protocol, "whoever holds the port now"
//! is the right answer.

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use needlecast_common::Prog;

use crate::decide::{decide_v4, decide_v6};
use crate::sock::Proto;

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    unsafe { decide_v4(&ctx, Prog::Sendmsg4, Proto::Udp) }
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    unsafe { decide_v6(&ctx, Prog::Sendmsg6, Proto::Udp) }
}
