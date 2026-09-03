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

    async fn round_trip(msg: &Msg) -> Msg {
        let mut buf = std::vec::Vec::new();
        wire::write(&mut buf, msg).await.expect("encodes");
        wire::read(&mut buf.as_slice()).await.expect("decodes")
    }

    #[tokio::test]
    async fn every_message_round_trips() {
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
            assert_eq!(round_trip(&msg).await, msg);
        }
    }

    #[tokio::test]
    async fn frames_are_length_delimited_so_two_can_share_a_stream() {
        let mut buf = std::vec::Vec::new();
        wire::write(&mut buf, &Msg::Ping).await.unwrap();
        wire::write(&mut buf, &Msg::Goodbye).await.unwrap();
        let mut cursor = buf.as_slice();
        assert_eq!(wire::read(&mut cursor).await.unwrap(), Msg::Ping);
        assert_eq!(wire::read(&mut cursor).await.unwrap(), Msg::Goodbye);
    }

    #[tokio::test]
    async fn an_oversized_length_prefix_is_refused_rather_than_allocated() {
        let mut buf = 0xFFFF_FFFFu32.to_be_bytes().to_vec();
        buf.extend_from_slice(b"whatever");
        let err = wire::read(&mut buf.as_slice()).await.expect_err("refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_truncated_frame_is_an_error_not_a_partial_message() {
        let mut buf = std::vec::Vec::new();
        wire::write(
            &mut buf,
            &Msg::Listeners {
                ports: std::vec![8080],
            },
        )
        .await
        .unwrap();
        buf.pop();
        assert!(wire::read(&mut buf.as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn a_listener_set_survives_the_managed_range_width() {
        let ports: std::vec::Vec<u16> = (8000..=8999).collect();
        assert_eq!(
            round_trip(&Msg::Listeners {
                ports: ports.clone()
            })
            .await,
            Msg::Listeners { ports }
        );
    }

    #[test]
    fn the_preamble_is_eight_stable_bytes() {
        assert_eq!(&preamble::encode(1), b"NDLC\x00\x00\x00\x01");
        assert_eq!(preamble::ours(), preamble::encode(VERSION));
        assert_eq!(preamble::LEN, preamble::ours().len());
    }

    #[test]
    fn a_preamble_round_trips_at_any_version() {
        for v in [0, 1, 7, 99, u32::MAX] {
            assert_eq!(preamble::decode(&preamble::encode(v)).unwrap(), v);
        }
    }

    #[test]
    fn a_foreign_peer_is_rejected_on_the_magic_rather_than_the_version() {
        let err = preamble::decode(b"HTTP/1.1").expect_err("rejected");
        assert!(err.to_string().contains("not a needlecast peer"), "{err}");
    }

    #[tokio::test]
    async fn a_short_preamble_is_an_error_not_a_partial_version() {
        let buf = b"NDLC\x00".to_vec();
        let err = preamble::read(&mut buf.as_slice())
            .await
            .expect_err("short");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_preamble_survives_the_socket() {
        let mut buf = std::vec::Vec::new();
        preamble::write(&mut buf, 42).await.unwrap();
        assert_eq!(preamble::read(&mut buf.as_slice()).await.unwrap(), 42);
    }
}

/// Length-delimited postcard. About one message per second, so this is a type-safety decision.
///
/// Neither function is cancellation-safe — a frame read half-way cannot be put back — so a caller
/// with timers to service reads on a dedicated task and receives the results over a channel.
pub mod wire {
    use super::Msg;
    use std::io;
    use std::vec;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    const MAX_FRAME: u32 = 1 << 20;

    pub async fn write<W: AsyncWrite + Unpin>(w: &mut W, msg: &Msg) -> io::Result<()> {
        let body = postcard::to_allocvec(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let len = u32::try_from(body.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
        w.write_all(&len.to_be_bytes()).await?;
        w.write_all(&body).await?;
        w.flush().await
    }

    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Msg> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len).await?;
        let len = u32::from_be_bytes(len);
        if len > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        let mut body = vec![0u8; len as usize];
        r.read_exact(&mut body).await?;
        postcard::from_bytes(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// The eight bytes ahead of any postcard frame, so two incompatible builds can still diagnose each
/// other. Here rather than in the daemon so a test exercises the shipped encoding rather than a
/// second copy of it.
pub mod preamble {
    use super::{MAGIC, VERSION};
    use std::io;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    pub const LEN: usize = 8;

    pub fn encode(version: u32) -> [u8; LEN] {
        let mut out = [0u8; LEN];
        out[..4].copy_from_slice(&MAGIC);
        out[4..].copy_from_slice(&version.to_be_bytes());
        out
    }

    /// `Err` names which of the two things is wrong, because "not needlecast at all" and "a
    /// needlecast that disagrees" want different responses from an operator.
    pub fn decode(buf: &[u8; LEN]) -> io::Result<u32> {
        if buf[..4] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                std::format!(
                    "not a needlecast peer: expected magic {:?}, got {:?}",
                    MAGIC,
                    &buf[..4]
                ),
            ));
        }
        Ok(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]))
    }

    pub async fn write<W: AsyncWrite + Unpin>(w: &mut W, version: u32) -> io::Result<()> {
        w.write_all(&encode(version)).await?;
        w.flush().await
    }

    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u32> {
        let mut buf = [0u8; LEN];
        r.read_exact(&mut buf).await?;
        decode(&buf)
    }

    /// What this build puts on the wire.
    pub fn ours() -> [u8; LEN] {
        encode(VERSION)
    }
}
