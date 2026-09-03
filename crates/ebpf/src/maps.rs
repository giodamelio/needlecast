//! Every map, declared once. All pinned, so `status` can read them without the daemon.
//!
//! Counters are indexed `program * stride + event`, so the stride in `needlecast_common` is larger
//! than the number of events: appending one must not shift every existing counter.

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap},
};
use needlecast_common::{
    counter_slot, tc_counter_slot, Config, Ev, Prog, SleeveConfig, TcEv, TcProg, COUNTER_SLOTS,
    TC_COUNTER_SLOTS,
};

/// Written once at startup; after that only `enabled` and the port range change.
#[map]
pub static CONFIG: Array<Config> = Array::pinned(1, 0);

#[map]
pub static COUNTERS: Array<u64> = Array::pinned(COUNTER_SLOTS, 0);

/// Cleared, never left stale, when the control connection drops: a stale set is worse than none.
#[map]
pub static DESKTOP_PORTS: HashMap<u16, u8> = HashMap::pinned(8192, 0);

#[map]
pub static SLEEVE_CONFIG: Array<SleeveConfig> = Array::pinned(1, 0);

#[map]
pub static TC_COUNTERS: Array<u64> = Array::pinned(TC_COUNTER_SLOTS, 0);

/// A missing slot is ignored: failing a decision because a diagnostic could not be recorded would
/// be the wrong trade.
#[inline(always)]
pub fn bump(prog: Prog, ev: Ev) {
    if let Some(slot) = COUNTERS.get_ptr_mut(counter_slot(prog, ev)) {
        unsafe { *slot += 1 };
    }
}

#[inline(always)]
pub fn tc_bump(prog: TcProg, ev: TcEv) {
    if let Some(slot) = TC_COUNTERS.get_ptr_mut(tc_counter_slot(prog, ev)) {
        unsafe { *slot += 1 };
    }
}
