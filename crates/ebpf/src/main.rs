//! needlecast's kernel side: eleven programs across two halves that never run on the same machine.
//!
//! - The **client** decides at `connect()` and `sendmsg()` whether a loopback destination has a
//!   local listener, rewriting to the tunnel address when it does not, and undoes that in
//!   `getpeername()` and `recvmsg()` so the application never learns it happened.
//! - The **server** rewrites an arriving packet's destination to `127.0.0.1` and the reply's source
//!   back, statelessly — ports are never translated, so the port pair identifies the flow.
//!
//! One program per file. Shared plumbing is in [`maps`], [`sock`] and [`packet`]; predicates that
//! need no context are in `needlecast_common::net`, where they can be unit tested on the host.

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

/// Unreachable — the verifier would reject a program that could panic. Required to link.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
