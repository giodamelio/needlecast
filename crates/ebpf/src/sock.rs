//! Raw access to a `cgroup_sock_addr` context.
//!
//! None of the helpers that matter have safe wrappers in aya, so this module is where that
//! unsafety is contained; the policy using it lives in `decide` and `restore`.

use aya_ebpf::{
    bindings::{
        bpf_sock_addr, bpf_sock_tuple, bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 as Tuple4,
        bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2 as Tuple6,
    },
    cty::c_void,
    helpers::{bpf_setsockopt, bpf_sk_lookup_tcp, bpf_sk_lookup_udp, bpf_sk_release},
};

/// 1 allows the operation, 0 fails it. needlecast redirects traffic, it never blocks it.
pub const ALLOW: i32 = 1;

/// The *caller's* namespace, not the loader's — so a container finds its own listener.
pub const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;

pub const SOL_TCP: i32 = 6;
pub const TCP_SYNCNT: i32 = 7;

#[derive(Clone, Copy, PartialEq)]
pub enum Proto {
    Tcp,
    Udp,
}

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

/// A zeroed source means only a *listening* socket can match, since an established one needs a
/// full four-tuple — so presence is a sufficient test and `bpf_sock.state` need not be read. A
/// wildcard `0.0.0.0` bind matches too, as it would for real delivery.
///
/// `tuple_size` must be the address-family variant's size, never the union's. Every non-null
/// result must be released; the verifier enforces that.
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

/// Returns the helper's return code.
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
