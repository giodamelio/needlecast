//! `connect4` and `connect6`: the moment the decision is made.
//!
//! This is the whole reason needlecast needs no rendezvous socket and no userspace proxy. The
//! kernel calls this program synchronously inside `connect()`, before a single packet exists, so
//! the destination can simply be changed and routing does the rest.
//!
//! It fires for TCP and for *connected* UDP sockets, which decide once here and keep that decision
//! for the life of the socket. Unconnected UDP goes through `sendmsg` instead.

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use needlecast_common::prog;

use crate::decide::{decide_v4, decide_v6};
use crate::sock::Proto;

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    unsafe { decide_v4(&ctx, prog::CONNECT4, Proto::Tcp) }
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    unsafe { decide_v6(&ctx, prog::CONNECT6, Proto::Tcp) }
}
