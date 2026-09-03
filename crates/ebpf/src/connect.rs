//! The moment the decision is made, and the reason needlecast needs no rendezvous socket or
//! userspace proxy: the kernel calls this synchronously inside `connect()`, before a packet
//! exists, so the destination can simply be changed and routing does the rest.
//!
//! TCP and *connected* UDP, which decide once here. Unconnected UDP goes through `sendmsg`.

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use needlecast_common::Prog;

use crate::decide::{decide_v4, decide_v6};
use crate::sock::Proto;

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    unsafe { decide_v4(&ctx, Prog::Connect4, Proto::Tcp) }
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    unsafe { decide_v6(&ctx, Prog::Connect6, Proto::Tcp) }
}
