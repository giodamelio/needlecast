//! needlecast's kernel side. One program per file; predicates that need no context live in
//! `needlecast_common::net`, where they can be unit tested on the host.

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
