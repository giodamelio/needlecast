//! `SIGTERM` and `SIGINT` as one thing to await, so both daemons unwind through the same path as a
//! clean return.
//!
//! Dying without unwinding is already safe — the `bpf_link`s drop with the process and the machine
//! reverts to stock — but it would leave the `needle` interface behind. Catching the signal is what
//! makes a clean exit leave no trace.

use anyhow::{Context, Result};
use tokio::signal::unix::{signal, Signal, SignalKind};

pub struct Shutdown {
    terminate: Signal,
    interrupt: Signal,
}

impl Shutdown {
    pub fn install() -> Result<Self> {
        Ok(Shutdown {
            terminate: signal(SignalKind::terminate()).context("registering SIGTERM")?,
            interrupt: signal(SignalKind::interrupt()).context("registering SIGINT")?,
        })
    }

    /// Cancellation-safe, so it can sit in a `select!` that loops without losing a signal that
    /// arrived while another arm was being served.
    pub async fn requested(&mut self) {
        tokio::select! {
            _ = self.terminate.recv() => {}
            _ = self.interrupt.recv() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// One test rather than several: a raised signal is process-wide, so anything asserting on its
    /// *absence* would see this one and fail whenever the two ran together.
    ///
    /// Raising is safe because installing has already replaced the default disposition — which is
    /// itself the thing worth proving, since getting it wrong kills the daemon instead.
    #[tokio::test]
    async fn both_signals_are_observed_rather_than_fatal() {
        let mut s = Shutdown::install().expect("install");

        // Nothing pending, so this must not resolve.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), s.requested())
                .await
                .is_err(),
            "resolved with no signal pending"
        );

        for signal in [libc::SIGTERM, libc::SIGINT] {
            assert_eq!(unsafe { libc::raise(signal) }, 0);
            tokio::time::timeout(Duration::from_secs(5), s.requested())
                .await
                .unwrap_or_else(|_| panic!("signal {signal} was not observed"));
        }
    }
}
