//! The control plane.
//!
//! Its one load-bearing job is liveness. Without it `connect4` keeps rewriting toward a desktop
//! that is gone, and the connection hangs on SYN retransmit instead of failing. The listener feed
//! is a latency optimisation on top: the desktop already refuses unserved ports correctly on its
//! own, this just saves the round trip.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use anyhow::{Context, Result};
use needlecast_common::proto::{wire, Msg, VERSION};

pub const PING_INTERVAL: Duration = Duration::from_secs(1);
/// How long without hearing anything before the peer is considered gone.
pub const LIVENESS_TIMEOUT: Duration = Duration::from_secs(3);
/// Socket read timeout. Deliberately much shorter than `LIVENESS_TIMEOUT`: both sides must be able
/// to act on their own timers, so a read returning empty has to be routine rather than fatal.
pub const POLL: Duration = Duration::from_millis(250);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// True when a read returned simply because nothing had arrived yet.
pub fn is_idle(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// Ports the desktop is serving on any address reachable through its own loopback: `127.0.0.1`,
/// `0.0.0.0`, `::1` and `::` are all reachable there, so all four count.
pub fn local_listeners() -> Result<BTreeSet<u16>> {
    let mut ports = BTreeSet::new();
    // TCP_LISTEN for TCP; a bound UDP socket sits in TCP_CLOSE.
    for (path, want_state) in [
        ("/proc/net/tcp", 0x0A),
        ("/proc/net/tcp6", 0x0A),
        ("/proc/net/udp", 0x07),
        ("/proc/net/udp6", 0x07),
    ] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        // sl | local_address | rem_address | st | ...
        for line in text.lines().skip(1) {
            let mut f = line.split_whitespace();
            let Some(local) = f.nth(1) else { continue };
            let Some(_rem) = f.next() else { continue };
            let Some(state) = f.next() else { continue };
            if u8::from_str_radix(state, 16).ok() != Some(want_state) {
                continue;
            }
            let Some((_, port)) = local.split_once(':') else {
                continue;
            };
            if let Ok(p) = u16::from_str_radix(port, 16) {
                ports.insert(p);
            }
        }
    }
    Ok(ports)
}

/// Desktop side. Answers heartbeats and publishes the listener set; holds no state about the
/// laptop, so a laptop that vanishes needs no cleanup here.
pub fn serve(bind: Ipv4Addr, port: u16, port_lo: u16, port_hi: u16) -> Result<()> {
    let listener = TcpListener::bind(SocketAddr::from((bind, port)))
        .with_context(|| format!("binding control port {bind}:{port}"))?;
    log::info!("control plane listening on {bind}:{port}");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        std::thread::spawn(move || {
            if let Err(e) = serve_one(stream, port_lo, port_hi) {
                log::info!("control connection ended: {e:#}");
            }
        });
    }
    Ok(())
}

fn serve_one(mut stream: TcpStream, port_lo: u16, port_hi: u16) -> Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(POLL))?;
    let peer = stream.peer_addr()?;

    match wire::read(&mut stream)? {
        Msg::Hello { version } if version == VERSION => {}
        Msg::Hello { version } => {
            log::warn!("{peer}: unsupported version {version}, refusing");
            return Ok(());
        }
        other => {
            log::warn!("{peer}: expected Hello, got {other:?}");
            return Ok(());
        }
    }
    wire::write(
        &mut stream,
        &Msg::Welcome {
            version: VERSION,
            port_lo,
            port_hi,
        },
    )?;

    let mut published: Option<BTreeSet<u16>> = None;
    let mut reader = stream.try_clone()?;
    loop {
        // Publish before blocking on a read, so the first snapshot arrives without waiting for a
        // heartbeat round trip.
        let now: BTreeSet<u16> = local_listeners()?
            .into_iter()
            .filter(|p| *p >= port_lo && *p <= port_hi)
            .collect();
        if published.as_ref() != Some(&now) {
            wire::write(
                &mut stream,
                &Msg::Listeners {
                    ports: now.iter().copied().collect(),
                },
            )?;
            published = Some(now);
        }

        match wire::read(&mut reader) {
            Ok(Msg::Ping) => wire::write(&mut stream, &Msg::Pong)?,
            Ok(Msg::Goodbye) => return Ok(()),
            Ok(_) => {}
            // Nothing arrived this tick. The laptop decides when to give up on us, so there is
            // nothing to do here but look at the listener set again.
            Err(e) if is_idle(&e) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// What the laptop learned from one successful session.
pub struct Session {
    pub stream: TcpStream,
    pub port_lo: u16,
    pub port_hi: u16,
}

/// Laptop side. Dials and completes the handshake; the caller owns the enabled flag, because the
/// ordering of clearing it matters more than anything else in this module.
pub fn dial(addr: SocketAddr) -> Result<Session> {
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .with_context(|| format!("dialling {addr}"))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(POLL))?;
    wire::write(&mut stream, &Msg::Hello { version: VERSION })?;
    match wire::read(&mut stream)? {
        Msg::Welcome {
            version,
            port_lo,
            port_hi,
        } if version == VERSION => Ok(Session {
            stream,
            port_lo,
            port_hi,
        }),
        other => anyhow::bail!("unexpected reply to Hello: {other:?}"),
    }
}
