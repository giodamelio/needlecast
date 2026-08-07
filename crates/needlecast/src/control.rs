//! Plain TCP over the tunnel. WireGuard authenticates it and the peer's identity *is* its tunnel
//! source address, so there is no TLS and no token.
//!
//! Its one load-bearing job is liveness: without it the client keeps rewriting toward a server that
//! is gone, and connections hang on SYN retransmit instead of failing.

use std::collections::BTreeSet;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
pub use needlecast_common::proto::EXIT_VERSION_MISMATCH;
use needlecast_common::proto::{wire, Msg, MAGIC, VERSION};

use crate::shutdown::Shutdown;

/// A stale enabled flag only costs something while a connection is open, so the heartbeat is fast
/// then and slow otherwise.
pub const PING_INTERVAL: Duration = Duration::from_secs(1);
pub const IDLE_PING_INTERVAL: Duration = Duration::from_secs(30);

pub const LIVENESS_MULTIPLIER: u32 = 3;

/// Must exceed the client's slowest liveness deadline, or an idle laptop is disconnected on a timer
/// rather than because anything is wrong. Without it a suspended one holds a thread until TCP
/// keepalive notices, which takes two hours.
pub const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Both sides act on their own timers, so a read returning empty has to be routine rather than
/// fatal — which means this must stay well under any deadline.
pub const POLL: Duration = Duration::from_millis(250);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub const LISTENER_POLL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionMismatch {
    pub ours: u32,
    pub theirs: u32,
}

impl std::fmt::Display for VersionMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "protocol version mismatch: this machine speaks {}, the peer speaks {}. \
             Upgrade both to the same needlecast.",
            self.ours, self.theirs
        )
    }
}

impl std::error::Error for VersionMismatch {}

/// Nothing had arrived yet, as opposed to anything being wrong.
pub fn is_idle(e: &io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn write_preamble(w: &mut impl Write, version: u32) -> io::Result<()> {
    w.write_all(&MAGIC)?;
    w.write_all(&version.to_be_bytes())?;
    w.flush()
}

/// Retries while the socket is merely idle, so [`POLL`] does not look like a failed handshake.
fn read_preamble(r: &mut impl Read, deadline: Duration) -> Result<u32> {
    let mut buf = [0u8; 8];
    let mut got = 0;
    let started = Instant::now();
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => anyhow::bail!("peer closed during the handshake"),
            Ok(n) => got += n,
            Err(e) if is_idle(&e) => {
                if started.elapsed() >= deadline {
                    anyhow::bail!("no handshake within {deadline:?}");
                }
            }
            Err(e) => return Err(e).context("reading the handshake"),
        }
    }
    if buf[..4] != MAGIC {
        anyhow::bail!(
            "not a needlecast peer: expected magic {:?}, got {:?}",
            MAGIC,
            &buf[..4]
        );
    }
    Ok(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]))
}

/// Both sides send before either compares, so each can name the other's version in its error
/// rather than reporting an unexplained disconnect.
pub fn exchange_version(stream: &mut TcpStream, deadline: Duration) -> Result<()> {
    write_preamble(stream, VERSION)?;
    let mut reader = stream.try_clone()?;
    let theirs = read_preamble(&mut reader, deadline)?;
    if theirs != VERSION {
        return Err(VersionMismatch {
            ours: VERSION,
            theirs,
        }
        .into());
    }
    Ok(())
}

/// Ports reachable through this machine's own loopback, which includes wildcard binds.
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
        ports.extend(parse_proc_net(&text, want_state));
    }
    Ok(ports)
}

/// `sl | local_address | rem_address | st | ...`
fn parse_proc_net(text: &str, want_state: u8) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in text.lines().skip(1) {
        let mut f = line.split_whitespace();
        let Some(local) = f.nth(1) else { continue };
        let Some(_rem) = f.next() else { continue };
        let Some(state) = f.next() else { continue };
        if u8::from_str_radix(state, 16).ok() != Some(want_state) {
            continue;
        }
        // IPv6 rows carry a 32-hex-digit address, so the port is after the *last* colon.
        let Some((_, port)) = local.rsplit_once(':') else {
            continue;
        };
        if let Ok(p) = u16::from_str_radix(port, 16) {
            ports.push(p);
        }
    }
    ports
}

/// Established connections to `peer`, as `(local_port, peer_port)`.
pub fn established_with(peer: Ipv4Addr) -> Vec<(u16, u16)> {
    const TCP_ESTABLISHED: u8 = 0x01;
    let Ok(text) = std::fs::read_to_string("/proc/net/tcp") else {
        return Vec::new();
    };
    parse_established(&text, peer, TCP_ESTABLISHED)
}

fn parse_established(text: &str, peer: Ipv4Addr, want_state: u8) -> Vec<(u16, u16)> {
    // /proc/net/tcp writes IPv4 addresses as a little-endian hex word.
    let want = format!("{:08X}", u32::from_le_bytes(peer.octets()));
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let mut f = line.split_whitespace();
        let Some(local) = f.nth(1) else { continue };
        let Some(rem) = f.next() else { continue };
        let Some(state) = f.next() else { continue };
        if u8::from_str_radix(state, 16).ok() != Some(want_state) {
            continue;
        }
        let (Some((_, lport)), Some((raddr, rport))) =
            (local.rsplit_once(':'), rem.rsplit_once(':'))
        else {
            continue;
        };
        if !raddr.eq_ignore_ascii_case(&want) {
            continue;
        }
        if let (Ok(l), Ok(r)) = (
            u16::from_str_radix(lport, 16),
            u16::from_str_radix(rport, 16),
        ) {
            out.push((l, r));
        }
    }
    out
}

/// Holds no state about the client, so one that vanishes needs no cleanup here.
pub fn serve(
    bind: Ipv4Addr,
    port: u16,
    port_lo: u16,
    port_hi: u16,
    shutdown: &Shutdown,
) -> Result<()> {
    let listener = TcpListener::bind(SocketAddr::from((bind, port)))
        .with_context(|| format!("binding control port {bind}:{port}"))?;
    listener.set_nonblocking(true)?;
    log::info!("control plane listening on {bind}:{port}");

    while !shutdown.requested() {
        match listener.accept() {
            Ok((stream, peer)) => {
                std::thread::spawn(move || match serve_one(stream, port_lo, port_hi) {
                    Ok(()) => log::info!("{peer}: control connection ended"),
                    Err(e) => match e.downcast_ref::<VersionMismatch>() {
                        // Fatal by design: no negotiation, no compatibility shim.
                        Some(m) => {
                            log::error!("{peer}: {m}");
                            std::process::exit(EXIT_VERSION_MISMATCH);
                        }
                        None => log::info!("{peer}: control connection failed: {e:#}"),
                    },
                });
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => shutdown.sleep(POLL),
            Err(e) => return Err(e).context("accepting a control connection"),
        }
    }
    Ok(())
}

fn serve_one(mut stream: TcpStream, port_lo: u16, port_hi: u16) -> Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(POLL))?;
    exchange_version(&mut stream, CONNECT_TIMEOUT)?;
    wire::write(&mut stream, &Msg::Welcome { port_lo, port_hi })?;

    let mut published: Option<BTreeSet<u16>> = None;
    let mut reader = stream.try_clone()?;
    let mut last_heard = Instant::now();
    let mut last_scan = Instant::now()
        .checked_sub(LISTENER_POLL)
        .unwrap_or_else(Instant::now);
    loop {
        // Before the read, so the first snapshot does not wait for a heartbeat round trip.
        if last_scan.elapsed() >= LISTENER_POLL {
            last_scan = Instant::now();
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
        }

        match wire::read(&mut reader) {
            Ok(msg) => {
                last_heard = Instant::now();
                match msg {
                    Msg::Ping => wire::write(&mut stream, &Msg::Pong)?,
                    Msg::Goodbye => return Ok(()),
                    _ => {}
                }
            }
            Err(e) if is_idle(&e) => {}
            Err(e) => return Err(e.into()),
        }

        if last_heard.elapsed() >= SERVER_IDLE_TIMEOUT {
            anyhow::bail!("silent for {SERVER_IDLE_TIMEOUT:?}, closing");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Beat {
    Wait,
    Ping,
    Expired,
}

/// Separated from the socket so the timing is testable without waiting in real time: every method
/// takes the current instant rather than reading the clock.
pub struct Heartbeat {
    interval: Duration,
    last_ping: Instant,
    last_heard: Instant,
}

impl Heartbeat {
    pub fn new(now: Instant) -> Self {
        Heartbeat {
            interval: IDLE_PING_INTERVAL,
            last_ping: now,
            last_heard: now,
        }
    }

    pub fn heard(&mut self, now: Instant) {
        self.last_heard = now;
    }

    /// The deadline is derived from whatever interval is in force *now*, so relaxing it cannot
    /// retroactively expire a connection that was healthy a moment ago.
    pub fn set_active(&mut self, active: bool) {
        self.interval = if active {
            PING_INTERVAL
        } else {
            IDLE_PING_INTERVAL
        };
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn deadline(&self) -> Duration {
        self.interval * LIVENESS_MULTIPLIER
    }

    pub fn tick(&mut self, now: Instant) -> Beat {
        if now.duration_since(self.last_heard) >= self.deadline() {
            return Beat::Expired;
        }
        if now.duration_since(self.last_ping) >= self.interval {
            self.last_ping = now;
            return Beat::Ping;
        }
        Beat::Wait
    }
}

pub struct Session {
    pub stream: TcpStream,
    pub port_lo: u16,
    pub port_hi: u16,
}

/// The caller owns the enabled flag: the order it is cleared in matters more than anything else
/// here.
pub fn dial(addr: SocketAddr) -> Result<Session> {
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .with_context(|| format!("dialling {addr}"))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(POLL))?;
    exchange_version(&mut stream, CONNECT_TIMEOUT)?;
    match wire::read(&mut stream) {
        Ok(Msg::Welcome { port_lo, port_hi }) => Ok(Session {
            stream,
            port_lo,
            port_hi,
        }),
        Ok(other) => anyhow::bail!("expected Welcome, got {other:?}"),
        Err(e) => Err(e).context("reading Welcome"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_listen_lines_yield_their_ports() {
        // Two listeners and one established socket, which must not be counted.
        let text = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1
   1: 00000000:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1
   2: 0100007F:1F90 0100007F:B3C4 01 00000000:00000000 00:00000000 00000000     0        0 12347 1
";
        let mut ports = parse_proc_net(text, 0x0A);
        ports.sort_unstable();
        assert_eq!(ports, vec![8080, 8081]);
    }

    #[test]
    fn a_bound_udp_socket_is_in_tcp_close_not_listen() {
        let text = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F75 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 999 2
";
        assert_eq!(parse_proc_net(text, 0x07), vec![8053]);
        assert!(parse_proc_net(text, 0x0A).is_empty());
    }

    #[test]
    fn ipv6_listen_lines_parse() {
        let text = "\
  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A
";
        assert_eq!(parse_proc_net(text, 0x0A), vec![8080]);
    }

    #[test]
    fn a_header_only_table_yields_nothing() {
        assert!(parse_proc_net("  sl  local_address rem_address   st\n", 0x0A).is_empty());
        assert!(parse_proc_net("", 0x0A).is_empty());
    }

    #[test]
    fn a_truncated_line_is_skipped_rather_than_panicking() {
        let text = "header\n   0: 0100007F:1F90\n   1: garbage\n";
        assert!(parse_proc_net(text, 0x0A).is_empty());
    }

    #[test]
    fn established_rows_are_matched_on_the_peer_address() {
        // 010012C6 is 198.18.0.1 in /proc/net/tcp's little-endian hex.
        let text = "\
  sl  local_address rem_address   st
   0: 020012C6:A5F0 010012C6:1F90 01 rest
   1: 020012C6:A5F1 0100007F:1F90 01 rest
   2: 020012C6:A5F2 010012C6:1F91 0A rest
";
        let found = parse_established(text, Ipv4Addr::new(198, 18, 0, 1), 0x01);
        assert_eq!(found, vec![(42480, 8080)], "only the established peer row");
    }

    #[test]
    fn no_established_rows_when_nothing_talks_to_the_peer() {
        let text = "header\n   0: 0100007F:1F90 0100007F:B3C4 01 rest\n";
        assert!(parse_established(text, Ipv4Addr::new(198, 18, 0, 1), 0x01).is_empty());
    }

    #[test]
    fn the_preamble_is_eight_stable_bytes() {
        let mut buf = Vec::new();
        write_preamble(&mut buf, 1).unwrap();
        assert_eq!(buf, b"NDLC\x00\x00\x00\x01");
    }

    #[test]
    fn a_preamble_round_trips() {
        let mut buf = Vec::new();
        write_preamble(&mut buf, 7).unwrap();
        assert_eq!(read_preamble(&mut buf.as_slice(), POLL).unwrap(), 7);
    }

    #[test]
    fn a_foreign_peer_is_rejected_on_the_magic_rather_than_the_version() {
        let buf = b"HTTP/1.1".to_vec();
        let err = read_preamble(&mut buf.as_slice(), POLL).expect_err("rejected");
        assert!(err.to_string().contains("not a needlecast peer"), "{err}");
    }

    #[test]
    fn a_short_preamble_is_an_error_not_a_partial_version() {
        let buf = b"NDLC\x00".to_vec();
        assert!(read_preamble(&mut buf.as_slice(), POLL).is_err());
    }

    #[test]
    fn a_mismatch_names_both_versions() {
        let m = VersionMismatch { ours: 1, theirs: 4 };
        let s = m.to_string();
        assert!(s.contains('1') && s.contains('4'), "{s}");
        assert!(s.contains("Upgrade both"), "{s}");
    }

    #[test]
    fn the_timers_are_ordered_so_no_side_gives_up_first_by_accident() {
        assert!(POLL < PING_INTERVAL);
        assert!(PING_INTERVAL < IDLE_PING_INTERVAL);
        assert!(IDLE_PING_INTERVAL * LIVENESS_MULTIPLIER < SERVER_IDLE_TIMEOUT);
    }

    mod heartbeat {
        use super::*;

        fn at(base: Instant, secs: u64) -> Instant {
            base + Duration::from_secs(secs)
        }

        #[test]
        fn an_idle_heartbeat_pings_every_thirty_seconds() {
            let t0 = Instant::now();
            let mut hb = Heartbeat::new(t0);
            assert_eq!(hb.interval(), IDLE_PING_INTERVAL);
            assert_eq!(hb.tick(at(t0, 29)), Beat::Wait);
            assert_eq!(hb.tick(at(t0, 30)), Beat::Ping);
            assert_eq!(hb.tick(at(t0, 31)), Beat::Wait);
        }

        #[test]
        fn an_active_heartbeat_pings_every_second() {
            let t0 = Instant::now();
            let mut hb = Heartbeat::new(t0);
            hb.set_active(true);
            assert_eq!(hb.interval(), PING_INTERVAL);
            assert_eq!(hb.tick(t0 + Duration::from_millis(999)), Beat::Wait);
            assert_eq!(hb.tick(at(t0, 1)), Beat::Ping);
        }

        /// An implementation that pinged only after a read deadlocks two idle peers and kills the
        /// connection every few seconds, forever.
        #[test]
        fn pings_continue_while_nothing_is_received() {
            let t0 = Instant::now();
            let mut hb = Heartbeat::new(t0);
            hb.set_active(true);
            let mut pings = 0;
            for s in 1..=5 {
                if hb.tick(at(t0, s)) == Beat::Ping {
                    pings += 1;
                    // A pong comes back, which is the only thing keeping it alive.
                    hb.heard(at(t0, s));
                }
            }
            assert_eq!(pings, 5);
        }

        #[test]
        fn silence_for_three_intervals_expires_the_connection() {
            let t0 = Instant::now();
            let mut hb = Heartbeat::new(t0);
            hb.set_active(true);
            assert_eq!(hb.deadline(), Duration::from_secs(3));
            assert_eq!(hb.tick(at(t0, 2)), Beat::Ping);
            assert_eq!(hb.tick(at(t0, 3)), Beat::Expired);
        }

        #[test]
        fn hearing_something_pushes_the_deadline_out() {
            let t0 = Instant::now();
            let mut hb = Heartbeat::new(t0);
            hb.set_active(true);
            hb.heard(at(t0, 2));
            assert_eq!(hb.tick(at(t0, 3)), Beat::Ping);
            assert_eq!(hb.tick(at(t0, 4)), Beat::Ping);
            assert_eq!(hb.tick(at(t0, 5)), Beat::Expired);
        }

        #[test]
        fn slowing_down_does_not_retroactively_expire_a_healthy_connection() {
            let t0 = Instant::now();
            let mut hb = Heartbeat::new(t0);
            hb.set_active(true);
            hb.heard(at(t0, 2));
            hb.set_active(false);
            assert_eq!(hb.deadline(), Duration::from_secs(90));
            // At the fast interval this would already have expired; at the slow one it is fine.
            assert_eq!(hb.tick(at(t0, 10)), Beat::Wait);
            assert_eq!(hb.tick(at(t0, 30)), Beat::Ping);
            // Still inside the ninety-second deadline measured from the last thing heard.
            assert_eq!(hb.tick(at(t0, 91)), Beat::Ping);
            assert_eq!(hb.tick(at(t0, 93)), Beat::Expired);
        }

        #[test]
        fn speeding_up_shortens_the_deadline_immediately() {
            let t0 = Instant::now();
            let mut hb = Heartbeat::new(t0);
            assert_eq!(hb.tick(at(t0, 5)), Beat::Wait);
            hb.set_active(true);
            assert_eq!(hb.tick(at(t0, 5)), Beat::Expired);
        }

        #[test]
        fn expiry_takes_precedence_over_a_due_ping() {
            let t0 = Instant::now();
            let mut hb = Heartbeat::new(t0);
            hb.set_active(true);
            assert_eq!(hb.tick(at(t0, 60)), Beat::Expired);
        }
    }
}
