//! Wake userspace when the set of loopback listeners might have changed.
//!
//! **Nothing here decides anything.** `control::local_listeners` re-reads `/proc/net/*` and stays
//! the only authority on what is listening; these programs exist so that read happens when
//! something changed rather than four times a second forever. A spurious wakeup therefore costs
//! one wasted scan, while a missed one costs a server that is never advertised — so the filters
//! below are deliberately loose in the direction of waking too often.
//!
//! Four hooks, because no single one covers both protocols:
//!
//! | Hook | Covers |
//! |---|---|
//! | `sock/inet_sock_set_state` | TCP entering and leaving `LISTEN` |
//! | `cgroup/post_bind4`, `post_bind6` | UDP `bind()`, which has no state transition to watch |
//! | `cgroup/sock_release` | a UDP socket going away |
//!
//! TCP is deliberately *not* woken on from `post_bind`: a TCP socket is bound before it listens, so
//! that wakeup would always scan too early and find nothing.

use aya_ebpf::{
    macros::{cgroup_sock, map, tracepoint},
    maps::{Array, RingBuf},
    programs::{SockContext, TracePointContext},
};
use needlecast_common::{net, FeedConfig, TcEv, TcProg, TCP_LISTEN};

use crate::maps::tc_bump;

/// One page. Each event is four bytes and userspace drains on every wakeup, so this only has to
/// absorb a burst; overflow is survivable because the scan that follows reads the real state.
#[map]
pub static LISTENER_EVENTS: RingBuf = RingBuf::pinned(4096, 0);

#[map]
pub static FEED_CONFIG: Array<FeedConfig> = Array::pinned(1, 0);

/// 1 allows the operation. These programs observe; they never block a bind or a close.
const ALLOW: i32 = 1;

#[inline(always)]
fn wake(port: u16) {
    tc_bump(TcProg::Feed, TcEv::Total);
    match LISTENER_EVENTS.reserve::<u32>(0) {
        Some(mut entry) => {
            entry.write(port as u32);
            entry.submit(0);
        }
        // Survivable: userspace rescans on the wakeups it does get, and the scan is what produces
        // the answer. Counted because a full ring buffer means the consumer has stalled.
        None => tc_bump(TcProg::Feed, TcEv::StoreErr),
    }
}

#[tracepoint]
pub fn listener_state(ctx: TracePointContext) -> u32 {
    let Some(cfg) = FEED_CONFIG.get(0) else {
        return 0;
    };
    // SAFETY: `read_at` is a bounds-checked `bpf_probe_read` at a runtime offset, so a wrong
    // offset yields an error rather than an out-of-bounds read.
    let old: i32 = match unsafe { ctx.read_at(cfg.oldstate_off as usize) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let new: i32 = match unsafe { ctx.read_at(cfg.newstate_off as usize) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // Entering or leaving LISTEN. Every other transition belongs to an established connection and
    // cannot change what is being served.
    if old != TCP_LISTEN && new != TCP_LISTEN {
        return 0;
    }
    let port: u16 = match unsafe { ctx.read_at(cfg.sport_off as usize) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if net::port_in_range(port, cfg.port_lo, cfg.port_hi) {
        wake(port);
    }
    0
}

/// SAFETY: `protocol` is readable from `bpf_sock` under every attach type used here.
#[inline(always)]
fn is_udp(ctx: &SockContext) -> bool {
    unsafe { (*ctx.sock).protocol == net::IPPROTO_UDP as u32 }
}

/// UDP only: a TCP socket is bound before it listens, so waking here would scan before there is
/// anything to find, and the tracepoint would have to wake us again at the actual transition.
#[inline(always)]
fn wake_for_bind(ctx: &SockContext) -> i32 {
    let Some(cfg) = FEED_CONFIG.get(0) else {
        return ALLOW;
    };
    if !is_udp(ctx) {
        return ALLOW;
    }
    // `src_port` is host byte order here, unlike almost everything else in these programs.
    // `__sock_filter_check_attach_type` permits reading it under `POST_BIND4`/`POST_BIND6` and
    // nowhere else, which is why `listener_release` below cannot do the same.
    let port = unsafe { (*ctx.sock).src_port as u16 };
    if net::port_in_range(port, cfg.port_lo, cfg.port_hi) {
        wake(port);
    }
    ALLOW
}

#[cgroup_sock(post_bind4)]
pub fn listener_bind4(ctx: SockContext) -> i32 {
    wake_for_bind(&ctx)
}

#[cgroup_sock(post_bind6)]
pub fn listener_bind6(ctx: SockContext) -> i32 {
    wake_for_bind(&ctx)
}

/// Every UDP socket closing, not just one in the managed range, because the verifier will not let
/// this attach type read `src_port`.
///
/// The cost is a wasted scan per DNS lookup; the alternative is a served UDP port that is withdrawn
/// only when something else happens to wake us, which is indistinguishable from a hang. Wakeups are
/// coalesced in userspace, and an idle machine still produces none — which the 250ms poll this
/// replaced could not say.
#[cgroup_sock(sock_release)]
pub fn listener_release(ctx: SockContext) -> i32 {
    if is_udp(&ctx) {
        wake(0);
    }
    ALLOW
}
