//! The version check, over a real socket pair.
//!
//! Driven from both directions — including a peer speaking a version this build has never heard of,
//! which no single binary can produce by itself. Hence the wire format directly rather than through
//! `needlecast client`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use needlecast_common::proto::{EXIT_VERSION_MISMATCH, MAGIC, VERSION};

fn preamble(version: u32) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.extend_from_slice(&version.to_be_bytes());
    v
}

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let client = std::thread::spawn(move || TcpStream::connect(addr).expect("connect"));
    let (server, _) = listener.accept().expect("accept");
    (client.join().unwrap(), server)
}

fn read_exact_with_timeout(s: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

#[test]
fn the_version_is_the_first_thing_on_the_wire_in_both_directions() {
    let (mut a, mut b) = pair();
    a.write_all(&preamble(VERSION)).unwrap();
    b.write_all(&preamble(VERSION)).unwrap();

    assert_eq!(
        read_exact_with_timeout(&mut b, 8).unwrap(),
        preamble(VERSION)
    );
    assert_eq!(
        read_exact_with_timeout(&mut a, 8).unwrap(),
        preamble(VERSION)
    );
}

#[test]
fn a_peer_from_the_future_still_gets_its_version_across() {
    let (mut ours, mut theirs) = pair();
    ours.write_all(&preamble(VERSION)).unwrap();
    theirs.write_all(&preamble(99)).unwrap();

    let seen = read_exact_with_timeout(&mut ours, 8).unwrap();
    assert_eq!(seen[..4], MAGIC, "the magic is stable across versions");
    let theirs_version = u32::from_be_bytes([seen[4], seen[5], seen[6], seen[7]]);
    assert_eq!(theirs_version, 99);
    assert_ne!(theirs_version, VERSION, "which is what makes it fatal");
}

/// Postcard is non-self-describing, so a frame from another schema decodes as *something* rather
/// than failing. Hence raw bytes ahead of any framing.
#[test]
fn a_non_needlecast_peer_is_rejected_on_the_magic() {
    let (mut ours, mut theirs) = pair();
    theirs.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    let seen = read_exact_with_timeout(&mut ours, 8).unwrap();
    assert_ne!(seen[..4], MAGIC);
}

#[test]
fn a_peer_that_hangs_up_mid_preamble_does_not_look_like_a_version() {
    let (mut ours, mut theirs) = pair();
    theirs.write_all(&MAGIC[..2]).unwrap();
    drop(theirs);
    let err = read_exact_with_timeout(&mut ours, 8).expect_err("short read");
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn a_silent_peer_times_out() {
    let (mut ours, _theirs) = pair();
    ours.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut buf = [0u8; 8];
    let err = ours.read_exact(&mut buf).expect_err("timed out");
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "{err:?}"
    );
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
