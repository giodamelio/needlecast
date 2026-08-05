//! Raw access to a `cgroup_sock_addr` context.
//!
//! None of the helpers that matter here have safe wrappers in aya — `bpf_sk_lookup_tcp`,
//! `bpf_sk_lookup_udp`, `bpf_sk_release`, `bpf_get_netns_cookie` and `bpf_setsockopt` are all raw
//! bindings re-exported from `aya-ebpf-bindings`. This module is where that unsafety is contained;
//! the policy that uses it lives in `decide` and `restore`.

use aya_ebpf::{
    bindings::{
        bpf_sock_addr, bpf_sock_tuple, bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 as Tuple4,
        bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2 as Tuple6,
    },
    cty::c_void,
    helpers::{bpf_setsockopt, bpf_sk_lookup_tcp, bpf_sk_lookup_udp, bpf_sk_release},
};

/// Every `cgroup_sock_addr` program returns 1 to allow the operation. Returning 0 fails it, which
/// needlecast never does: it redirects traffic, it does not block it.
pub const ALLOW: i32 = 1;

/// Resolve the lookup in the *caller's* namespace, not the loader's. This is what makes a container
/// connecting to a port its own namespace is listening on find that socket and be left alone.
pub const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;

pub const SOL_TCP: i32 = 6;
pub const TCP_SYNCNT: i32 = 7;

#[derive(Clone, Copy, PartialEq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// The destination port the application asked for, in host order.
#[inline(always)]
pub unsafe fn port_of(sa: *mut bpf_sock_addr) -> u16 {
    u16::from_be((*sa).user_port as u16)
}

#[inline(always)]
pub unsafe fn read_v6(sa: *mut bpf_sock_addr) -> [u32; 4] {
    [
        (*sa).user_ip6[0],
        (*sa).user_ip6[1],
        (*sa).user_ip6[2],
        (*sa).user_ip6[3],
    ]
}

#[inline(always)]
pub unsafe fn write_v6(sa: *mut bpf_sock_addr, w: [u32; 4]) {
    (*sa).user_ip6[0] = w[0];
    (*sa).user_ip6[1] = w[1];
    (*sa).user_ip6[2] = w[2];
    (*sa).user_ip6[3] = w[3];
}

/// Is anything on this machine listening on the destination?
///
/// The source in the tuple is zeroed, which means only a *listening* socket can match — an
/// established socket needs a full four-tuple. So presence is a sufficient test and reading
/// `bpf_sock.state` is unnecessary. A wildcard `0.0.0.0` bind matches too, because the kernel's
/// wildcard rule applies to the helper lookup exactly as it does to real delivery.
///
/// `tuple_size` must be exactly the size of the address-family variant, never the union size, and
/// every non-null result must be released — the verifier enforces the second.
#[inline(always)]
pub unsafe fn has_local_listener_v4(
    ctx: *mut c_void,
    daddr_be: u32,
    port: u16,
    proto: Proto,
) -> bool {
    let mut tuple: bpf_sock_tuple = core::mem::zeroed();
    tuple.__bindgen_anon_1.ipv4 = Tuple4 {
        saddr: 0,
        daddr: daddr_be,
        sport: 0,
        dport: port.to_be(),
    };
    let size = core::mem::size_of::<Tuple4>() as u32;
    let sk = match proto {
        Proto::Tcp => bpf_sk_lookup_tcp(ctx, &mut tuple, size, BPF_F_CURRENT_NETNS, 0),
        Proto::Udp => bpf_sk_lookup_udp(ctx, &mut tuple, size, BPF_F_CURRENT_NETNS, 0),
    };
    if sk.is_null() {
        return false;
    }
    bpf_sk_release(sk as *mut c_void);
    true
}

#[inline(always)]
pub unsafe fn has_local_listener_v6(
    ctx: *mut c_void,
    daddr: [u32; 4],
    port: u16,
    proto: Proto,
) -> bool {
    let mut tuple: bpf_sock_tuple = core::mem::zeroed();
    tuple.__bindgen_anon_1.ipv6 = Tuple6 {
        saddr: [0; 4],
        daddr,
        sport: 0,
        dport: port.to_be(),
    };
    let size = core::mem::size_of::<Tuple6>() as u32;
    let sk = match proto {
        Proto::Tcp => bpf_sk_lookup_tcp(ctx, &mut tuple, size, BPF_F_CURRENT_NETNS, 0),
        Proto::Udp => bpf_sk_lookup_udp(ctx, &mut tuple, size, BPF_F_CURRENT_NETNS, 0),
    };
    if sk.is_null() {
        return false;
    }
    bpf_sk_release(sk as *mut c_void);
    true
}

/// `setsockopt` on the socket the context belongs to. Returns the helper's return code.
#[inline(always)]
pub unsafe fn set_int_sockopt(ctx: *mut c_void, level: i32, optname: i32, mut value: i32) -> i64 {
    bpf_setsockopt(
        ctx,
        level,
        optname,
        &mut value as *mut i32 as *mut c_void,
        core::mem::size_of::<i32>() as i32,
    )
}
