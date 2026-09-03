//! The version check, over a real socket pair.
//!
//! Driven from both directions — including a peer speaking a version this build has never heard of,
//! which no single binary can produce by itself. Hence the wire format directly rather than through
//! `needlecast client`.
//!
//! The bytes come from `proto::preamble`, so this exercises the shipped encoding rather than a
//! second copy of it that could drift.

use std::time::Duration;

use needlecast_common::proto::{preamble, EXIT_VERSION_MISMATCH, MAGIC, VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (client.expect("connect"), accepted.expect("accept").0)
}

/// Every read here is bounded, so a hang is a failure rather than a stuck suite.
async fn read_exact_with_timeout(s: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut buf))
        .await
        .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut)))?;
    Ok(buf)
}

#[tokio::test]
async fn the_version_is_the_first_thing_on_the_wire_in_both_directions() {
    let (mut a, mut b) = pair().await;
    a.write_all(&preamble::ours()).await.unwrap();
    b.write_all(&preamble::ours()).await.unwrap();

    assert_eq!(
        read_exact_with_timeout(&mut b, preamble::LEN)
            .await
            .unwrap(),
        preamble::ours()
    );
    assert_eq!(
        read_exact_with_timeout(&mut a, preamble::LEN)
            .await
            .unwrap(),
        preamble::ours()
    );
}

#[tokio::test]
async fn a_peer_from_the_future_still_gets_its_version_across() {
    let (mut ours, mut theirs) = pair().await;
    ours.write_all(&preamble::ours()).await.unwrap();
    theirs.write_all(&preamble::encode(99)).await.unwrap();

    let theirs_version = preamble::read(&mut ours).await.expect("decodes");
    assert_eq!(theirs_version, 99);
    assert_ne!(theirs_version, VERSION, "which is what makes it fatal");
}

/// Postcard is non-self-describing, so a frame from another schema decodes as *something* rather
/// than failing. Hence raw bytes ahead of any framing.
#[tokio::test]
async fn a_non_needlecast_peer_is_rejected_on_the_magic() {
    let (mut ours, mut theirs) = pair().await;
    theirs.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    let err = preamble::read(&mut ours).await.expect_err("rejected");
    assert!(err.to_string().contains("not a needlecast peer"), "{err}");
}

#[tokio::test]
async fn a_peer_that_hangs_up_mid_preamble_does_not_look_like_a_version() {
    let (mut ours, mut theirs) = pair().await;
    theirs.write_all(&MAGIC[..2]).await.unwrap();
    drop(theirs);
    let err = preamble::read(&mut ours).await.expect_err("short read");
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn a_silent_peer_times_out() {
    let (mut ours, _theirs) = pair().await;
    let err = tokio::time::timeout(Duration::from_millis(200), preamble::read(&mut ours))
        .await
        .expect_err("timed out");
    assert!(err.to_string().contains("deadline"), "{err}");
}

/// Named by the module's `RestartPreventExitStatus=`, so changing it silently makes a version
/// mismatch a crash loop.
#[test]
fn the_version_mismatch_exit_code_is_ex_config() {
    assert_eq!(EXIT_VERSION_MISMATCH, 78);
}

#[test]
fn the_magic_is_the_four_bytes_every_version_must_agree_on() {
    assert_eq!(&MAGIC, b"NDLC");
}
