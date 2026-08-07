//! Whether the peer is alive, one-shot negotiation, and the set of ports the server is serving.

use serde::{Deserialize, Serialize};

/// A mismatch is **fatal on both sides**: postcard is non-self-describing, so a field added on one
/// side would be misread rather than rejected.
///
/// Exchanged in a fixed eight-byte preamble ahead of any postcard frame, so two incompatible builds
/// can still diagnose each other.
pub const VERSION: u32 = 1;

/// Fixed, because the client has to know where to dial. The client binds nothing.
pub const DEFAULT_CONTROL_PORT: u16 = 47653;

/// `EX_CONFIG`, so a supervisor can name it in `RestartPreventExitStatus=` and make the failure
/// stationary rather than a crash loop.
pub const EXIT_VERSION_MISMATCH: i32 = 78;

/// Must stay byte-identical forever, or a future build cannot diagnose an older one.
pub const MAGIC: [u8; 4] = *b"NDLC";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Msg {
    /// Carries the managed range, which the client adopts rather than configuring its own.
    Welcome {
        port_lo: u16,
        port_hi: u16,
    },
    Ping,
    Pong,
    /// The complete set, not a delta, so a lost update cannot leave the two sides disagreeing.
    Listeners {
        ports: alloc::vec::Vec<u16>,
    },
    /// So the peer acts immediately rather than waiting for the heartbeat to time out.
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

/// Length-delimited postcard. About one message per second, so this is a type-safety decision.
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
