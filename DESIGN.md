# needlecast: the design

The kernel side is settled and proven — see [FINDINGS.md](FINDINGS.md) for what was measured and
[PLAN.md](PLAN.md) for how. This document covers everything above it: how the tunnel comes up, how
the two sides find each other, what the control protocol is, and how the whole thing behaves when
one machine disappears, which it does constantly.

All of it is built. What is described here is what the code does, not what it should eventually do;
where a decision was reversed by measurement, the reversal is recorded rather than the original.

## Scope

One laptop, one desktop. Both normally reachable by DNS name, neither reliably online. No pairing
step, no config file, no state directory. Two commands:

```
needlecast server ./secret cesium.gio.ninja     # on the desktop
needlecast client ./secret cadmium.gio.ninja    # on the laptop
```

Each side is given the *other* machine's name. That is the whole configuration.

Explicit non-goals: multiple peers, NAT traversal, relaying, riding on an existing WireGuard or
Tailscale interface. Each of those is a project rather than a feature.

## Identity: one shared secret

Both keypairs are derived from the same file, so neither side has anything the other lacks and
there is nothing to exchange:

```
server_private = HKDF-SHA256(secret, info = "needlecast server key v1")
client_private = HKDF-SHA256(secret, info = "needlecast client key v1")
```

Each side computes both keypairs, keeps its own private key, and uses the other's public key as
the WireGuard peer. Generate the secret once with 32 bytes of real randomness and copy it across:

```
head -c 32 /dev/urandom | base64 > secret
```

**The secret file is both machines' identity.** Anyone holding it can impersonate either side, and
there is no revocation short of replacing it on both. That is the price of having no pairing step,
and for two personal machines it is the right trade — but it means `chmod 600`, and it means a lost
laptop is a rotate-the-secret event.

## The tunnel

**Interface name: `needle`.** `IF_NAMESIZE` is 16, so 15 characters are usable; six is comfortable
and unlikely to collide with anything.

**Addresses: `198.18.0.1` (server) and `198.18.0.2` (client)**, hardcoded, `/24` on the interface
so the on-link route exists. The peer's `allowed-ips` is its `/32`, which is as tight as it can be
with exactly one peer.

`198.18.0.0/15` is RFC 2544 space, reserved for benchmarking network equipment. It is the
best-kept-free range in IPv4:

| Range | Why not |
|---|---|
| `10/8`, `192.168/16` | Home routers, corporate VPNs |
| `172.16/12` | Docker's default bridge is `172.17/16`; compose walks up from `172.18` |
| `100.64/10` | CGNAT — and Tailscale's range |
| `169.254/16` | See below |
| `240/4` | Class E; many stacks refuse to route it |
| **`198.18/15`** | Reserved, never routed, not used by NAT gear or container runtimes |

### Why not link-local (`169.254/16`)

It looks appealing — "reserved for local use" — but it is the one range the system actively uses on
its own:

- **The kernel and DHCP clients assign these addresses themselves.** IPv4LL (RFC 3927) hands out a
  `169.254.x.x` address to any interface whose DHCP fails. This is not theoretical: in our own VM
  tests, `dhcpcd` assigned `169.254.212.102` to the dummy interface we created. We would be
  competing for space the system hands out automatically.
- **Cloud metadata lives at `169.254.169.254`** on AWS, GCP, Azure and DigitalOcean. Running
  needlecast on any cloud host would put us next door to it.
- **`scope link` is not just a label.** The kernel treats link-local addresses as single-hop:
  source address selection (RFC 6724) deprioritises them, and various paths assume the destination
  is on the same segment. Our interface is point-to-point and NOARP, which is a semantic mismatch.
- **IPv4LL does ARP-based conflict detection**, so another process claiming an address could probe
  and object to ours.

`198.18/15` has none of that. Nothing assigns it, nothing routes it, nothing special-cases it.

The eventual right answer is an IPv6 ULA — a random `/48` makes collision impossible — but the
desktop datapath is IPv4-only today, so that waits for v6 support there.

**WireGuard port: a fixed high number**, same on both sides. It only has to be stable and
memorable, not secret.

### Endpoint management

needlecast creates and owns the interface over netlink, via `defguard_wireguard_rs`; it does not
exist otherwise. (`wireguard-control` was the original choice; `defguard_wireguard_rs` also does
address assignment and link-up, which removes the need for hand-written `netlink-packet-route`
code.)

Startup is **idempotent**: if `needle` already exists — a previous run crashed, or the process was
killed — it is removed and recreated rather than adopted. See the decision on that below.

The endpoint is a DNS name, so **needlecast re-resolves it and calls `set_endpoint` itself**.
WireGuard resolves an endpoint once and then holds that address forever; if the peer moves, the
tunnel is dead until something updates it. This is the classic `wg-quick` footgun and it is
entirely ours to handle:

- Re-resolve on every reconnect attempt while disconnected.
- Re-resolve every few minutes while connected, and update if the answer changed.

Both sides get the other's endpoint configured, so whichever machine returns first can initiate the
handshake. Be clear-eyed that the *laptop's* name only helps while it is directly reachable — from
a café it is behind NAT, and the desktop simply waits. `persistentKeepalive` from the laptop keeps
that path open.

## The control protocol

Plain TCP over the tunnel, on a fixed port bound to the server's tunnel address. WireGuard
authenticates it and the peer's identity is its tunnel source address, so there is no TLS, no
certificate and no token.

**Framing: length-delimited postcard.** Postcard is compact and non-self-describing, which means it
has no tolerance at all for schema drift — a field added on one side breaks the other. Rather than
pretend otherwise, the protocol makes that explicit:

**The first exchange is a version check, and a mismatch is fatal on both sides.** No negotiation, no
compatibility shims, no silently-degraded mode. Upgrading means upgrading both, which for two
machines you control is the honest constraint anyway.

That check cannot itself be a postcard message: a frame from a different schema decodes as
*something* rather than failing, so a version field inside the first message is unreadable exactly
when it matters. It is instead **eight raw bytes** — the magic `NDLC` and a big-endian version —
ahead of any framing. Both sides send before either compares, so each can name the other's version
in its error rather than reporting an unexplained disconnect.

The one operational wrinkle: a supervisor with `Restart=always` turns a version mismatch into a
crash loop. Use `RestartPreventExitStatus=` on the version-mismatch exit code so the failure is
loud and *stationary* rather than loud and repeating.

Messages after the handshake: `Ping`/`Pong`, and `Listeners` carrying the full set of ports the
server is serving in the managed range. Full sets rather than deltas, so a dropped update cannot
leave the two sides disagreeing indefinitely.

## `needlecast status`

Works on either side, and reads **kernel and filesystem state directly — no IPC with the daemon**:

- WireGuard state over netlink: interface up, last handshake, bytes each way
- The enabled flag and listener set from the pinned BPF maps, which is also how it knows whether
  the control connection is up
- Whether the daemon is alive, from whether its programs are still *loaded* — not from the pins,
  which survive a crash
- Active forwarded connections from `/proc/net/tcp`, filtered by the tunnel address
- The per-program decision counters that already exist

The point of taking no IPC dependency is that **`status` works when the daemon is wedged or dead**,
which is exactly when it is worth having. It also means there is no second interface to keep in
sync with the daemon's internal state.

## Resilience

The laptop is offline most of the time and the desktop is not always up either. Both sides must
degrade to "as if needlecast were not installed" and recover without intervention.

### Client state machine

```
Disconnected
  → resolve peer DNS, set_endpoint
  → dial control port
  → version check (fatal on mismatch)
  → wait for first Listeners snapshot
  → Ready: enabled = 1, listener map populated

on any error:
  enabled = 0        ← first, always
  clear listener map
  back off, retry
```

Clearing the enabled flag before anything else is the one ordering that matters: there must never
be a window where the programs rewrite toward a desktop known to be gone.

Backoff doubles from 200ms to a **5s cap**. Reconnects are cheap and the person waiting is you.

### Reconnecting promptly rather than eventually

Three signals bypass the backoff and trigger an immediate re-resolve and re-dial:

- **Suspend/resume.** `CLOCK_MONOTONIC` stops while suspended; `CLOCK_BOOTTIME` does not. The gap
  between them *is* time spent suspended, so a jump in that gap detects resume with no systemd
  integration and no new dependency.
- **Network change.** A new address or a changed default route means the old connection is dead
  even though the socket does not know it yet.
- **A failed heartbeat**, which is the fallback when neither of the above fires.

### Server side

Stateless: it holds nothing about the client, so a client that vanishes needs no cleanup.

**But it needs an idle timeout**, which the POC did not have. Letting the client decide when to give
up means a suspended laptop leaves a server thread blocked on a socket that will never speak again,
reaped only by TCP keepalive — which defaults to *two hours*. Flap a few times and threads
accumulate.

So the server closes a connection silent for **two minutes**, a generous multiple of the slowest
heartbeat the client can settle into. `tests/resilience.nix` `SIGSTOP`s the client and watches the
connection go.

### What each side does while the other is gone

| | Client (laptop) | Server (desktop) |
|---|---|---|
| Peer offline | `enabled = 0`; `localhost:8080` behaves exactly as if needlecast were not installed | Nothing; the tc programs stay attached and never match |
| Peer returns | Reconnects within one backoff interval, or immediately on resume/network change | Accepts; nothing to restore |
| Own process dies | `bpf_link`s drop, machine reverts to stock | Same |
| Own process restarts | Replaces the leftover `needle` interface | Same |

There is a useful interaction between two mechanisms already built: the `TCP_SYNCNT` cap bounds the
damage of a *stale* enabled flag to a few seconds. So even when detection lags, the worst case is
one connection that takes about seven seconds to fail instead of failing instantly — which means
the heartbeat can afford to be slower when idle without hurting the experience.

## Security posture

Worth stating plainly, because the design grants real access:

- The server makes **every loopback port in the managed range** reachable to anyone holding the
  secret. People bind things to `127.0.0.1` precisely because they assume it is unreachable —
  databases with trust auth, debug endpoints, unauthenticated admin UIs.
- **The managed port range is the only limit.** No deny-list, no per-port allowlist — see the
  decision below. That is why the firewall rules are narrow: anything that widened them past the
  range would quietly undo the only guarantee here.
- The secret file is both identities. A stolen laptop is a rotate-everywhere event.
- WireGuard is doing all the authentication and encryption. There is no second layer.

## What the firewall has to allow

The datapath crosses netfilter, which the POC never noticed because every VM suite ran with the
firewall off. The forwarded connection is inbound-initiated, so conntrack does not cover the SYN:
the ports have to be opened.

On the server, scoped to the tunnel interface: **the managed port range, and the control port.**
Ports are never translated, so the destination port of a forwarded packet is the one the client
asked for — which makes the range exactly the right filter, and keeps it the only limit on what the
secret grants. On both halves, the WireGuard port, so whichever machine is reachable first can start
the handshake.

Two things this is deliberately *not*:

- **Not `trustedInterfaces`.** It would work, and it would also expose every service bound to
  `0.0.0.0` on ports outside the managed range.
- **Not a rule matching the destination address.** `127.0.0.0/8` on the tunnel interface looks
  tighter and is looser: tc only rewrites what is addressed to the tunnel address on a port in
  range, so an address-matched accept would let a peer reach *any* loopback port by addressing it
  directly. See FINDINGS.md.

On NixOS this is ordinary `networking.firewall` options — no hand-written rules, and nothing that
depends on iptables versus nftables. Elsewhere it is one sentence: allow inbound UDP on the
WireGuard port, and on `needle` allow inbound TCP and UDP for the managed range plus TCP on the
control port.

## Decisions

**A clean exit removes the `needle` interface.** Stopping needlecast leaves no trace: no interface,
no addresses, no sysctl. Startup still has to adopt a leftover interface after a crash, so
idempotent setup is required regardless.

**No port deny-list.** The server exposes every loopback port in the managed range. The range is
the only limit, so keep anything you do not want reachable outside it. See the security posture
above — this is a deliberate choice, not an oversight.

**`status` distinguishes the cases.** "never started" (no interface, no pinned maps), "not running"
(state present, no process), "running but disconnected" (`enabled = 0`), and "connected". All of it
is inferable from state `status` already reads, so it costs nothing.

The one subtlety, learned the hard way: **the pinned maps are not evidence of a running daemon.**
They appear during load and survive a crashed process, so a `status` that keyed on them would call
a dead machine "connected". Liveness comes from whether the programs are still *loaded*, because
those disappear with the process holding their links — the same property that makes a crash safe.

**A startup that replaces its interface rather than adopting it.** `create_interface` is already
idempotent, so adoption would be free; the reason not to is that it would adopt whatever state the
crash left, including a link someone downed and a stale peer set. Removing and recreating costs one
handshake, is deterministic, and cannot disturb anything else because the interface is ours alone.

## Installing it

`nix/module.nix` exposes `services.needlecast.server` and `.client`, so each machine names the other
and points at a secret:

```nix
services.needlecast.client = {
  enable = true;
  peer = "cadmium.gio.ninja";
  secretFile = "/var/lib/needlecast/secret";
};
```

Two things in the unit are load bearing rather than cosmetic:

- **`LoadCredential`** for the secret, so it is never in the store and never on the command line.
- **`RestartPreventExitStatus=78`**, so a protocol version mismatch — which retrying cannot fix —
  is loud and stationary instead of a crash loop that buries the one log line explaining it.

## The idle tunnel: what tearing down actually costs

The intuition is that tearing the tunnel down when idle trades a slower first connection for
battery. **It does not.** It trades a *failed* first connection.

The reason is that the decision is made synchronously inside `connect()`, in BPF, which cannot
block or wake a daemon. If the control connection is down, `enabled` is 0; `connect4` declines;
the kernel finds nothing on `127.0.0.1:8080` and returns `ECONNREFUSED` **instantly**. There is no
SYN to retransmit, because loopback refuses immediately. The connection does not wait for the
tunnel — it fails, and only the *second* attempt succeeds.

Nor does keeping `enabled` set while the tunnel is down help by itself: that is exactly the stale
flag the control plane exists to prevent, and it converts an instant correct refusal into a
`TCP_SYNCNT`-bounded hang.

So there are three real positions:

| | Idle cost | First connection after idle |
|---|---|---|
| Heartbeat every 1s | one small packet per second | instant, correct |
| **Heartbeat backing off to ~30s when no connections are open** | one packet per 30s | instant, correct; at most a `TCP_SYNCNT`-bounded delay if the desktop died during the idle window |
| Tear the tunnel down | nothing | **fails**; the next one works |

The middle row gets essentially all of the battery saving without the failure. It is also cheap
because of an interaction already built: the `TCP_SYNCNT` cap bounds the damage of a stale enabled
flag to a few seconds, so a slow heartbeat's worst case is one connection taking about seven
seconds to fail rather than failing instantly.

Worth noting too that the case people picture when they say "idle" — the lid is shut — costs
nothing either way, because the process is frozen. Only idle-and-awake is affected, and there a
packet every 30 seconds is not measurable against anything else the machine is doing.

**Recommendation: adaptive heartbeat, no teardown.** Fast while connections are open, backing off
to ~30s when none are, immediate on resume or network change.

**Settled: adaptive heartbeat, no teardown.** Built and measured. The client pings once a second
while `/proc/net/tcp` shows a flow to the tunnel peer and once every thirty seconds when it does
not; the liveness deadline is three intervals, so it tightens and relaxes with it. The server
tolerates two minutes of silence before closing, which is a generous multiple of the slowest
heartbeat and is what reaps a suspended laptop.
