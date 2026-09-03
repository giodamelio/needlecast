//! Tell the client what it asked for.
//!
//! Without this, anything that logs or checks its peer learns the server's tunnel address — which
//! is exactly the leak the design exists to prevent.

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use needlecast_common::Prog;

use crate::restore::{restore_v4, restore_v6};

#[cgroup_sock_addr(getpeername4)]
pub fn getpeername4(ctx: SockAddrContext) -> i32 {
    unsafe { restore_v4(&ctx, Prog::Getpeername4) }
}

#[cgroup_sock_addr(getpeername6)]
pub fn getpeername6(ctx: SockAddrContext) -> i32 {
    unsafe { restore_v6(&ctx, Prog::Getpeername6) }
}
