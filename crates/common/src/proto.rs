//! The control connection between the laptop and the desktop.
//!
//! It runs as plain TCP over the tunnel. WireGuard authenticates it, and the peer's identity *is*
//! its tunnel source address, so there is no TLS, no certificate, and no token here.
//!
//! It carries exactly three things: whether the server is alive, one-shot negotiation, and the
//! set of ports the server is serving.

use serde::{Deserialize, Serialize};

/// Bumped whenever anything below changes shape. A mismatch is **fatal on both sides** — no
/// negotiation, no compatibility shim, no silently-degraded mode — because postcard is
/// non-self-describing and a field added on one side would otherwise be misread rather than
/// rejected. Upgrading means upgrading both, which for two machines you control is the honest
/// constraint anyway.
///
/// The version itself is exchanged in a fixed eight-byte preamble ahead of any postcard frame, so
/// two incompatible builds can still diagnose each other. See `control::exchange_version`.
pub const VERSION: u32 = 1;

/// The server's control port. Fixed, because the client has to know where to dial; the client side
/// binds nothing, so it needs no such number.
pub const DEFAULT_CONTROL_PORT: u16 = 47653;

/// Exit status for a version mismatch. `EX_CONFIG` from sysexits, chosen so a supervisor can name
/// it in `RestartPreventExitStatus=` and make the failure loud and *stationary* rather than a
/// crash loop.
pub const EXIT_VERSION_MISMATCH: i32 = 78;

/// The eight-byte handshake preamble's magic, which must stay byte-identical forever so that two
/// builds speaking different schemas can still diagnose each other.
pub const MAGIC: [u8; 4] = *b"NDLC";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Msg {
    /// The server's first frame. Carries the managed range, which the server is authoritative
    /// over — the client adopts it rather than configuring its own.
    Welcome {
        port_lo: u16,
        port_hi: u16,
    },
    Ping,
    Pong,
    /// The complete set the server is serving. Sent once after `Welcome` and again whenever it
    /// changes, so a lost delta cannot leave the two sides disagreeing indefinitely.
    Listeners {
        ports: alloc::vec::Vec<u16>,
    },
    /// Sent before a clean shutdown so the peer can act immediately rather than waiting for the
    /// heartbeat to time out.
    Goodbye,
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(msg: &Msg) -> Msg {
        let mut buf = std::vec::Vec::new();
        wire::write(&mut buf, msg).expect("encodes");
        wire::read(&mut buf.as_slice()).expect("decodes")
    }

    #[test]
    fn every_message_round_trips() {
        for msg in [
            Msg::Welcome {
                port_lo: 8000,
                port_hi: 8999,
            },
            Msg::Ping,
            Msg::Pong,
            Msg::Listeners {
                ports: std::vec![8080, 8081, 8443],
            },
            Msg::Listeners { ports: std::vec![] },
            Msg::Goodbye,
        ] {
            assert_eq!(round_trip(&msg), msg);
        }
    }

    #[test]
    fn frames_are_length_delimited_so_two_can_share_a_stream() {
        let mut buf = std::vec::Vec::new();
        wire::write(&mut buf, &Msg::Ping).unwrap();
        wire::write(&mut buf, &Msg::Goodbye).unwrap();
        let mut cursor = buf.as_slice();
        assert_eq!(wire::read(&mut cursor).unwrap(), Msg::Ping);
        assert_eq!(wire::read(&mut cursor).unwrap(), Msg::Goodbye);
    }

    #[test]
    fn an_oversized_length_prefix_is_refused_rather_than_allocated() {
        let mut buf = 0xFFFF_FFFFu32.to_be_bytes().to_vec();
        buf.extend_from_slice(b"whatever");
        let err = wire::read(&mut buf.as_slice()).expect_err("refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_truncated_frame_is_an_error_not_a_partial_message() {
        let mut buf = std::vec::Vec::new();
        wire::write(
            &mut buf,
            &Msg::Listeners {
                ports: std::vec![8080],
            },
        )
        .unwrap();
        buf.pop();
        assert!(wire::read(&mut buf.as_slice()).is_err());
    }

    /// Postcard is non-self-describing, so this is not a hypothetical: bytes meant as one variant
    /// decode as another rather than failing. It is why the version preamble exists.
    #[test]
    fn a_listener_set_survives_the_managed_range_width() {
        let ports: std::vec::Vec<u16> = (8000..=8999).collect();
        assert_eq!(
            round_trip(&Msg::Listeners {
                ports: ports.clone()
            }),
            Msg::Listeners { ports }
        );
    }
}

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
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        let mut body = vec![0u8; len as usize];
        r.read_exact(&mut body)?;
        postcard::from_bytes(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}
