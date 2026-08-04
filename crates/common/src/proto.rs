//! The control connection between the laptop and the desktop.
//!
//! It runs as plain TCP over the tunnel. WireGuard authenticates it, and the peer's identity *is*
//! its tunnel source address, so there is no TLS, no certificate, and no token here.
//!
//! It carries exactly three things: whether the desktop is alive, one-shot negotiation, and the
//! set of ports the desktop is serving.

use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;

/// The sleeve's control port. Fixed, because the laptop has to know where to dial; the laptop side
/// binds nothing, so it needs no such number.
pub const DEFAULT_CONTROL_PORT: u16 = 47653;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Msg {
    Hello {
        version: u32,
    },
    Welcome {
        version: u32,
        port_lo: u16,
        port_hi: u16,
    },
    Ping,
    Pong,
    /// The complete set the desktop is serving. Sent once after `Welcome` and again whenever it
    /// changes, so a lost delta cannot leave the two sides disagreeing indefinitely.
    Listeners {
        ports: alloc::vec::Vec<u16>,
    },
    /// Sent before a clean shutdown so the laptop can disable immediately rather than waiting for
    /// the heartbeat to time out.
    Goodbye,
}

extern crate alloc;

/// Length-delimited postcard. The message rate is about one per second, so this is a type-safety
/// decision rather than a performance one.
pub mod wire {
    use super::Msg;
    use std::io::{self, Read, Write};
    use std::vec;

    const MAX_FRAME: u32 = 1 << 20;

    pub fn write(w: &mut impl Write, msg: &Msg) -> io::Result<()> {
        let body = postcard::to_allocvec(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let len = u32::try_from(body.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
        w.write_all(&len.to_be_bytes())?;
        w.write_all(&body)?;
        w.flush()
    }

    pub fn read(r: &mut impl Read) -> io::Result<Msg> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len);
        if len > MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        let mut body = vec![0u8; len as usize];
        r.read_exact(&mut body)?;
        postcard::from_bytes(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}
