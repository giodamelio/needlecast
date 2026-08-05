//! `recvmsg4` and `recvmsg6`: the UDP counterpart to `getpeername`.
//!
//! A datagram sent to a rewritten destination comes back from that address, so `recvfrom()` would
//! report the desktop's tunnel address as the source. This restores it, which is what makes the
//! per-datagram re-decision in `sendmsg` invisible: a socket whose first datagram went to the
//! desktop and whose second went local sees `127.0.0.1` as the source of both.

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use needlecast_common::prog;

use crate::restore::{restore_v4, restore_v6};

#[cgroup_sock_addr(recvmsg4)]
pub fn recvmsg4(ctx: SockAddrContext) -> i32 {
    unsafe { restore_v4(&ctx, prog::RECVMSG4) }
}

#[cgroup_sock_addr(recvmsg6)]
pub fn recvmsg6(ctx: SockAddrContext) -> i32 {
    unsafe { restore_v6(&ctx, prog::RECVMSG6) }
}
