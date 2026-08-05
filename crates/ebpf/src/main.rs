//! needlecast's kernel side.
//!
//! Eleven programs across two halves that never run on the same machine:
//!
//! - The **laptop** decides at `connect()` and `sendmsg()` time whether a loopback destination has
//!   a local listener, and rewrites it to the desktop's tunnel address when it does not. A matching
//!   pair of programs undoes that rewrite in `getpeername()` and `recvmsg()`, so the application
//!   never learns it happened.
//! - The **desktop** rewrites the destination of an arriving packet to `127.0.0.1` and the source
//!   of the reply back to its tunnel address, statelessly — ports are never translated, so the port
//!   pair already identifies the flow. A third program reports the peer as `127.0.0.1`, so a server
//!   cannot distinguish a forwarded connection from a local one.
//!
//! Every program lives in its own file. The shared plumbing is in [`maps`], [`sock`] (socket
//! address contexts) and [`packet`] (skb contexts); pure predicates that need no context at all are
//! in `needlecast_common::net`, where they can be unit tested on the host.

#![no_std]
#![no_main]

mod maps;
mod packet;
mod sock;

mod decide;
mod restore;

mod connect;
mod getpeername;
mod recvmsg;
mod sendmsg;

mod sleeve_peer;
mod syncnt_probe;
mod tc_egress;
mod tc_ingress;

/// Unreachable: the crate is `panic = "abort"`, nothing here can panic, and the verifier would
/// reject a program that could. Required for the target to link.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
