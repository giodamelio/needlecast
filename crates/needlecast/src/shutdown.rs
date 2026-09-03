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

    /// Returns early when a signal arrives, so a backoff cannot delay the exit by its full length.
    pub async fn sleep(&mut self, total: std::time::Duration) {
        tokio::select! {
            _ = self.requested() => {}
            _ = tokio::time::sleep(total) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// One test rather than three: a raised signal is process-wide, so anything else asserting on
    /// its *absence* would see this one and fail whenever the two ran together.
    ///
    /// Raising is safe because installing has already replaced the default disposition — which is
    /// itself the thing worth proving, since getting it wrong kills the daemon instead.
    #[tokio::test]
    async fn a_signal_is_observed_rather_than_fatal_and_cuts_a_sleep_short() {
        let mut s = Shutdown::install().expect("install");

        let started = tokio::time::Instant::now();
        s.sleep(Duration::from_millis(300)).await;
        assert!(
            started.elapsed() >= Duration::from_millis(280),
            "returned early with no signal pending"
        );

        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        tokio::time::timeout(Duration::from_secs(5), s.requested())
            .await
            .expect("SIGTERM was not observed");

        assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
        let started = tokio::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(5), s.sleep(Duration::from_secs(30)))
            .await
            .expect("SIGINT did not cut the sleep short");
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
