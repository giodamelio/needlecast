//! Every map, declared once.
//!
//! All of them are pinned, so the control CLI and `needlecast status` can read them without going
//! through the running daemon — which is what makes `status` work when the daemon is wedged.
//!
//! The counter arrays are indexed `program * events + event`. That flat layout is why adding a
//! program means bumping `COUNT` in `needlecast_common` rather than appending: every existing
//! counter would otherwise shift.

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap},
};
use needlecast_common::{
    counter_slot, tc_counter_slot, Config, SleeveConfig, COUNTER_SLOTS, TC_COUNTER_SLOTS,
};

/// Laptop configuration, written once at startup and then only `enabled` is flipped.
#[map]
pub static CONFIG: Array<Config> = Array::pinned(1, 0);

/// Laptop decision counters.
#[map]
pub static COUNTERS: Array<u64> = Array::pinned(COUNTER_SLOTS, 0);

/// Ports the desktop currently serves. Only consulted when `Config::use_listener_map` is set.
/// Cleared, never left stale, when the control connection drops — a stale set is worse than none.
#[map]
pub static DESKTOP_PORTS: HashMap<u16, u8> = HashMap::pinned(8192, 0);

/// Desktop configuration, including the L3 offset that lets one program serve both device classes.
#[map]
pub static SLEEVE_CONFIG: Array<SleeveConfig> = Array::pinned(1, 0);

/// Desktop datapath counters.
#[map]
pub static TC_COUNTERS: Array<u64> = Array::pinned(TC_COUNTER_SLOTS, 0);

/// Increment a laptop counter. A missing slot is silently ignored: a counter is a diagnostic, and
/// failing a decision because a diagnostic could not be recorded would be the wrong trade.
#[inline(always)]
pub fn bump(prog: u32, ev: u32) {
    if let Some(slot) = COUNTERS.get_ptr_mut(counter_slot(prog, ev)) {
        unsafe { *slot += 1 };
    }
}

/// Increment a desktop counter.
#[inline(always)]
pub fn tc_bump(prog: u32, ev: u32) {
    if let Some(slot) = TC_COUNTERS.get_ptr_mut(tc_counter_slot(prog, ev)) {
        unsafe { *slot += 1 };
    }
}
