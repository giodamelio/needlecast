//! A flag both daemons poll, so `SIGTERM` unwinds through the same path as a clean return.
//!
//! Dying without unwinding is already safe — the `bpf_link`s drop with the process and the machine
//! reverts to stock — but it would leave the `needle` interface behind. Catching the signal is what
//! makes a clean exit leave no trace.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};

#[derive(Clone)]
pub struct Shutdown(Arc<AtomicBool>);

impl Shutdown {
    pub fn install() -> Result<Self> {
        let flag = Arc::new(AtomicBool::new(false));
        for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
            signal_hook::flag::register(signal, Arc::clone(&flag))
                .with_context(|| format!("registering signal {signal}"))?;
        }
        Ok(Shutdown(flag))
    }

    pub fn requested(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// Sleep in short slices so a signal is acted on promptly rather than at the end of a
    /// heartbeat interval. Returns early if shutdown was requested.
    pub fn sleep(&self, total: std::time::Duration) {
        const SLICE: std::time::Duration = std::time::Duration::from_millis(100);
        let deadline = std::time::Instant::now() + total;
        loop {
            if self.requested() {
                return;
            }
            // `Instant - Instant` panics when the right side is later, and time can cross the
            // deadline between the check and the subtraction. Saturating makes that a zero-length
            // remainder rather than a crash in the one code path a signal has to survive.
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return;
            }
            std::thread::sleep(SLICE.min(remaining));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_flag_is_not_set() {
        let s = Shutdown(Arc::new(AtomicBool::new(false)));
        assert!(!s.requested());
    }

    #[test]
    fn sleeping_returns_early_once_the_flag_is_set() {
        let flag = Arc::new(AtomicBool::new(false));
        let s = Shutdown(Arc::clone(&flag));
        let handle = {
            let flag = Arc::clone(&flag);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(150));
                flag.store(true, Ordering::Relaxed);
            })
        };
        let started = std::time::Instant::now();
        s.sleep(std::time::Duration::from_secs(30));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "slept {:?}, so the flag was not observed",
            started.elapsed()
        );
        handle.join().unwrap();
    }

    /// A zero or already-elapsed interval must return rather than panic on the `Instant`
    /// subtraction, because this is the one path a signal has to survive.
    #[test]
    fn a_zero_length_sleep_returns_immediately() {
        let s = Shutdown(Arc::new(AtomicBool::new(false)));
        let started = std::time::Instant::now();
        s.sleep(std::time::Duration::ZERO);
        assert!(started.elapsed() < std::time::Duration::from_millis(50));
    }

    #[test]
    fn sleeping_without_a_signal_waits_the_whole_interval() {
        let s = Shutdown(Arc::new(AtomicBool::new(false)));
        let started = std::time::Instant::now();
        s.sleep(std::time::Duration::from_millis(300));
        assert!(started.elapsed() >= std::time::Duration::from_millis(280));
    }
}
