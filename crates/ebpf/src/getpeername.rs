//! `getpeername4` and `getpeername6`: tell the client what it asked for.
//!
//! Without this a program that connects to `127.0.0.1:8080` and then calls `getpeername()` learns
//! the desktop's tunnel address, which is exactly the leak the design exists to prevent. Anything
//! that logs its peer, or checks it, would see through the whole arrangement.

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use needlecast_common::prog;

use crate::restore::{restore_v4, restore_v6};

#[cgroup_sock_addr(getpeername4)]
pub fn getpeername4(ctx: SockAddrContext) -> i32 {
    unsafe { restore_v4(&ctx, prog::GETPEERNAME4) }
}

#[cgroup_sock_addr(getpeername6)]
pub fn getpeername6(ctx: SockAddrContext) -> i32 {
    unsafe { restore_v6(&ctx, prog::GETPEERNAME6) }
}
