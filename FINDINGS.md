# Findings

What was observed, as opposed to what [PLAN.md](PLAN.md) assumed. Everything here was measured in
NixOS VM tests or Rust unit tests, not reasoned about.

```
nix flake check                        # every VM suite, both kernels
cargo nextest run --workspace          # the unit and integration tests, in under a second
cargo nextest run --profile vm         # the same VM suites, one test per suite
cargo nextest run --profile vm -E 'test(endtoend)'   # or just one of them
```

The unit tests also run inside the package build, so a broken predicate fails `nix build` rather
than waiting for someone to run them by hand. The `vm` binary is excluded there — it shells out to
`nix build`, which cannot happen inside a sandbox.

Twenty-three VM tests run: eleven suites on **6.18.41** (the target kernel, and the nixpkgs LTS) and
on **7.1.5** (`linuxPackages_latest`, a forward-compatibility check), plus `demo` on the target
kernel only. Every finding holds identically on both. Each test asserts the kernel it booted, so a
passing run is unambiguous about what it proved.

Eight suites drive the **shipped** binary — a secret file and a machine name, nothing else — so no
feature-gated code can be load bearing for anything they prove.

| Suite | Build | Nodes | Covers |
|---|---|---|---|
| `transport` | shipped | 2 | needlecast creating and owning `needle` from nothing but a secret |
| `endtoend` | shipped | 2 | Both halves together: `localhost:8080` on the client reaching the server |
| `control` | shipped | 2 | Liveness, the listener feed, the adaptive heartbeat, `TCP_SYNCNT` |
| `hostile` | shipped | 2 | Local takeover, clean failure, non-interference, protocol fidelity, load |
| `status` | shipped | 2 | All four states, each reached for real |
| `resilience` | shipped | 2 | Peer death and return, endpoint re-resolution, crash-and-adopt, idle reaping |
| `module` | shipped | 2 | The NixOS module: units, credentials, firewall rules |
| `demo` | shipped | 2 | The whole thing working, and nothing else — the one you boot to look around |
| `laptop` | testing | 1 | The client decision path: `connect4/6`, `getpeername4/6`, `sendmsg4/6`, `recvmsg4/6` |
| `isolation` | testing | 1 | Containers, manual netns, `PrivateNetwork`, plus negative controls |
| `datapath-ethernet` | testing | 2 | The server datapath over plain ethernet, both families |
| `datapath-wireguard` | testing | 2 | The same assertions over a real WireGuard tunnel |

`demo` is the odd one out on purpose: it asserts almost nothing, because its job is to be booted.

```
nix run .#demo
>>> start_all()

nix run .#demo-ssh -- client            # from another terminal, key-only root shell
nix run .#demo-ssh -- client curl -sf http://localhost:8080/hello.txt
```

Two things it taught, both of which would have made it useless at the moment you reached for it:
the test framework gives root an empty `hashedPasswordFile` that silently overrides `password`, so
password login can never work and the key has to be an `authorizedKeys` entry; and the interactive
driver does **not** run the test script, so anything the script creates does not exist when you boot
it by hand. The file the demo serves is declared in the unit instead.

## Headline

**Every load-bearing question is answered yes.** The architecture survives intact: the laptop
decides at `connect()` with a live socket lookup, rewrites the destination to the desktop's tunnel
address, and the desktop's tc programs deliver that into a `127.0.0.1`-bound server and rewrite the
reply on the way out. Nothing in userspace touches a byte on either side.

The two things that could have forced a redesign — a tc program delivering into a loopback-bound
socket, and checksums surviving GSO — both work.

## Question status

| # | Question | Answer |
|---|---|---|
| 1 | Can a tc program get a rewritten packet delivered to a server bound to `127.0.0.1`? | **Yes.** Needs `route_localnet` on the transport interface and nothing else |
| 2 | Can the reply be caught on egress and rewritten back? | **Yes**, for both Rung A and Rung B, on the transport interface. No program on `lo` is needed |
| 9 | Can the server be given a loopback peer without touching anything outside our interface? | **Yes** — a `cgroup/getpeername4` program reports `127.0.0.1`, changing nothing on the machine |
| 3 | Is `bpf_sk_lookup_tcp()` callable from `cgroup_sock_addr`? | **Yes** |
| 4 | Does `connect4` accept rewriting loopback to a non-loopback address, and does routing follow? | **Yes** |
| 5 | Do checksums survive `CHECKSUM_PARTIAL`, GSO and fragmentation? | **Yes.** 200MB transfer hash-identical, oversized UDP echoed byte-identical |
| 6 | Does `bpf_sk_lookup_udp()` work from `sendmsg4`, and can `recvmsg4` restore the source? | **Yes** |
| 7 | Which hook fires for connected vs unconnected UDP? | **Disjoint.** Connected uses `connect4` only; unconnected uses `sendmsg4` only |
| 8 | Is `bpf_setsockopt(TCP_SYNCNT)` permitted in `cgroup_sock_addr`? | **Yes**, verifier-accepted and returns 0 at runtime |
| 10 | Can the same be done for IPv6, where `::1` is the only loopback address? | **Yes**, but only by redirecting into `lo`. Unlike v4 that costs no sysctl |

---

# The laptop decision path

### `bpf_sk_lookup_tcp()` from `cgroup_sock_addr` works

Confirmed by scenarios that distinguish *which* server answered:

- Local listener on `127.0.0.1:8080`: the connection goes local, `connect4.local_listener`
  increments, `connect4.rewritten` does not.
- No local listener: `connect4.rewritten` increments and the connection lands on the target.
- Listener on `0.0.0.0:8080`: also wins, because the kernel's wildcard-match rule applies to the
  helper lookup exactly as it does to real delivery.

Details worth carrying forward:

- Pass `BPF_F_CURRENT_NETNS` (`-1i64 as u64`) as the `netns` argument.
- Zero the source in the `bpf_sock_tuple` and fill only `daddr`/`dport`. With a zeroed source only
  a listening socket can match, since an established socket needs a full four-tuple, so presence is
  a sufficient test and reading `bpf_sock.state` is unnecessary.
- `tuple_size` must be exactly `size_of::<Tuple4>()` (12) or `size_of::<Tuple6>()` (36), never the
  union size.
- `bpf_sk_release()` on every non-null result. The verifier enforces this.

### Rewriting loopback to a non-loopback address works

`connect4` writing `ctx->user_ip4` from `127.0.0.1` to `10.7.0.2` works and routing picks the
interface owning that address. Tested against a dummy interface rather than a second loopback
address, so it exercises the same path the tunnel design uses.

`bpf_get_netns_cookie(ctx)` is available in the same program type and returns a value equal to what
userspace reads from `getsockopt(SO_NETNS_COOKIE)`. That equality is what makes the container guard
implementable: the loader captures the cookie at startup and the program compares against it.

### UDP: the two hooks are disjoint

Measured, not inferred:

| Socket | `connect4.rewritten` | `sendmsg4.rewritten` |
|---|---|---|
| Connected (`connect()` then `send()`) | +1 | +0 |
| Unconnected (`sendto()`) | +0 | +1 |

Better than the plan assumed — they never both fire for the same datagram, so a shared decision
function cannot double-count.

**Unconnected sockets really do re-decide per datagram**, and this is now asserted rather than
claimed. One socket, two `sendto` calls with a local listener started in between:

```
peer=127.0.0.1:8080   data=udp-desktop:ping
peer2=127.0.0.1:8080  data2=udp-local2:ping
```

The first went to the target, the second went local, and `recvmsg4` restored `127.0.0.1:8080` as
the source both times — so the application cannot tell them apart. TCP has no equivalent behaviour:
an established connection is never re-evaluated.

### `bpf_setsockopt(TCP_SYNCNT)` is permitted

Accepted by the verifier, attaches, and returns 0 at runtime. The Phase 8 plan to cap the
SYN-timeout hang at a few seconds instead of two minutes is viable.

Tested as its own program (`connect4_syncnt_probe`) loaded independently, so a rejection would have
been an observable result rather than something that took the other eight programs down with it.
Worth keeping that shape for future capability probes.

---

# The desktop datapath

Rung A: rewrite only the destination inbound and only the source outbound, leaving the laptop's
tunnel address as the peer the server sees. Stateless, because ports are never translated and the
port pair already identifies the flow.

### It works, and the sysctl question has a smaller answer than expected

Baseline without the sleeve is `ECONNREFUSED`; with it, the connection reaches a server bound to
`127.0.0.1`. `ss` on the desktop during a held connection:

```
127.0.0.1:8081     10.7.0.1:59116
```

The local address is genuine loopback. The peer is the laptop's tunnel address, which is the known
Rung A limitation — Rung B's source rewrite is what makes that loopback too.

Each sysctl was toggled and the effect measured rather than assumed:

| Setting | Result |
|---|---|
| `net.ipv4.conf.<iface>.route_localnet=0` | **Breaks.** The SYN is dropped as martian, so it is a *timeout*, not a refusal |
| `net.ipv4.conf.<iface>.rp_filter=1` | Works |
| `net.ipv4.conf.all.rp_filter=1` | Works |
| `net.ipv4.conf.all.route_localnet` | Stays `0` throughout; the per-interface setting alone does the work |

So **one sysctl, scoped to one interface**. The plan expected to need `rp_filter=0` as well; it does
not, because the source address is the laptop's tunnel address, which is genuinely routable via
that interface, so strict reverse-path validation passes unaided.

The failure mode when `route_localnet` is off is worth knowing: a silent drop and a hung connect,
not a clean error.

**This is scoped to an interface needlecast owns.** `/proc/sys/net/ipv4/conf/` holds one directory
per interface; the kernel creates `wg0`'s when the interface appears and destroys it when it goes
away. So this is a property of needlecast's own interface, not a machine setting, and it cannot
outlive the daemon's interface. `all`, `default` and `lo` all stay at `0`, and the desktop suite
asserts that explicitly rather than leaving it to inspection.

Blast radius: it lets packets *arriving on wg0* address `127.0.0.0/8`. The only thing that can put
a packet on wg0 is a peer that passed WireGuard's authentication and matches allowed-ips, and
reaching the desktop's loopback ports is what the sleeve exists to do — so it grants nothing the
design was not already granting.

### Rung B: the peer is `127.0.0.1`, and nothing on the machine is touched

The requirement is that a desktop dev server cannot tell a forwarded connection from a local one.
Rung A fails it: the server sees the laptop's tunnel address. The fix is a `cgroup/getpeername4`
program on the desktop that reports the peer as `127.0.0.1` — the same address the server is bound
to, so what it is told is byte-identical to a genuinely local connection.

Measured as what the **server application** is told, since that is what the requirement is about:

| Mode | Server sees | `ss` shows |
|---|---|---|
| `rung-a` | `10.7.0.1` | `10.7.0.1` |
| **`rung-b`** | **`127.0.0.1`** | `10.7.0.1` |
| a genuinely local connection | `127.0.0.1` | `127.0.0.1` |

The test asserts the forwarded and the genuinely local case report the *same* string, so no
comparison a server can make through the socket API separates them — including an exact
`== 127.0.0.1` test, not just a `127.0.0.0/8` range check. There is deliberately nothing to
configure: the reported address is not a knob.

**This is the same mechanism the laptop already uses, run in reverse.** The laptop rewrites the
packet and uses `getpeername4` to hide that from the client; the desktop leaves the packet alone
and uses `getpeername4` to present loopback to the server. In both cases what must change is what
an application observes, not what the wire carries.

Nothing on the desktop is touched outside the transport interface, and the test asserts each
negative rather than trusting it: no route added to the local table, no `clsact` qdisc on `lo`, and
`all`/`lo`/`default` `route_localnet` all still `0`. The only configuration anywhere is the single
`net.ipv4.conf.<wg-iface>.route_localnet=1`, on the interface needlecast creates.

Gating matters, because `getpeername4` fires for every socket on the machine. The program reads
`ctx->sk` — available in `cgroup_sock_addr` — and rewrites only when the socket's own local address
is `127.0.0.1`, its local port is in the managed range, *and* the peer is the paired laptop's
tunnel address. Anything else returns on the first comparison.

**`ss` still shows the truth**, which is a feature rather than a gap: an operator debugging the
desktop sees the real tunnel address while the application sees loopback. The honest caveat is that
a server learning its peer outside the socket API — parsing `/proc/net/tcp`, or a sidecar reading
`ss` — sees `10.7.0.1`. Host-checking dev servers use the socket API.

Two alternatives were implemented and measured before this one, and both are deleted:

- **Rewriting the source for real on the wire** works, but the reply is then addressed into
  `127.0.0.0/8` and the kernel's own `local 127.0.0.0/8 dev lo` swallows it. Getting it back out
  needs either a route in the local table or a tc program on `lo` — a change to the machine either
  way. It also forces a *distinct* peer address such as `127.71.0.1`, since `127.0.0.1` gives the
  kernel nothing to route on, which is precisely the "almost but not quite local" outcome to avoid.
  It additionally requires a NOARP point-to-point transport: on an Ethernet link the reply's next
  hop is a `127/8` address the kernel tries to ARP for and never resolves, leaving the neighbour
  entry at `127.71.0.1 INCOMPLETE`.
- **A tc egress program on `lo`** catching the reply and redirecting it into the tunnel never
  worked in this implementation, and is ruled out regardless by the constraint that only interfaces
  needlecast creates may be touched.

One implementation note that cost a test cycle: the tc programs must treat Rung B as *identical* to
Rung A. Gating them on `mode != RUNG_A` broke the datapath, because ingress started rewriting the
source for the one mode whose entire point is not to.

### Rung C is rejected: redirecting into `lo` needs *more* sysctls, not fewer

The design conversation claimed that ending the ingress program with
`bpf_redirect(lo_ifindex, BPF_F_INGRESS)` would avoid `route_localnet` entirely, because "the packet
re-enters at lo, where loopback addresses are entirely normal". That was implemented and measured,
and it is **wrong**:

| Setting | Rung C |
|---|---|
| nothing | fails (hangs) |
| `<iface>.route_localnet` alone | fails |
| `lo.route_localnet` alone | fails |
| `lo` **and** `<iface>.route_localnet` | works |
| `all.route_localnet` | works |

The redirect only moves the *inbound* check to `lo`. The reply still originates from `127.0.0.1`
and leaves via the transport interface, which needs `route_localnet` there exactly as Rung A does.
So Rung C costs two interfaces where Rung A costs one, and the second is `lo` — an interface
needlecast does not own. It is strictly worse against the constraint that only interfaces
needlecast creates may be configured.

Two mechanical details learned while proving it, worth keeping if the redirect is ever needed for
another reason:

- `lo` is Ethernet-framed, so `dev_forward_skb` runs `eth_type_trans`, which consumes 14 bytes as a
  link header. A packet off an L3-only device such as `wg0` has none and needs
  `bpf_skb_change_head(skb, 14, 0)` first, or the IP header is eaten.
- More subtly, `eth_type_trans` also sets `pkt_type` from the destination MAC. A frame redirected
  off a real NIC still carries that NIC's MAC, which is not `lo`'s all-zero address, so it arrives
  as `PACKET_OTHERHOST` and `ip_rcv` drops it. Both device classes need a *fresh zeroed* header, not
  merely a present one. This is why the redirect failed on ethernet under every sysctl combination
  while working on WireGuard.

The implementation was removed rather than left behind a flag; a rejected design is worse as dead
code than as a recorded measurement.

### For IPv6 the same redirect is the *only* option, and it costs nothing

The v4 argument above inverts completely. There is exactly one loopback check in the whole IPv6
stack, `net/ipv6/ip6_input.c`:

```c
	if ((ipv6_addr_loopback(&hdr->saddr) ||
	     ipv6_addr_loopback(&hdr->daddr)) &&
	    !(dev->flags & IFF_LOOPBACK) &&
	    !netif_is_l3_master(dev))
		goto err;
```

It has no sysctl. RFC 4291 §2.5.3 is stated as a rule rather than a default, so there is no v6
`route_localnet` to look for. Two consequences:

- **Rung A cannot work.** Rewriting the destination to `::1` and returning `TC_ACT_OK` leaves the
  packet to be dropped in `ip6_rcv_core`. Measured, not assumed: the datapath suite runs the
  ingress program with `--no-v6-redirect` and gets `TIMEOUT` while `tc_ingress.rewritten_tcp` still
  climbs — the program did its work and the kernel discarded the result.
- **Rung C costs no sysctl**, because the check is on *input* only. `ipv6_addr_loopback` appears
  nowhere in the output path, so the reply leaves with a `::1` source unhindered and egress rewrites
  it as it does for v4. The reason Rung C lost for v4 — needing `route_localnet` on `lo` as well —
  simply does not exist here. Nothing on `lo` is configured or attached; the redirect is an action
  taken by needlecast's own program on its own interface.

The two mechanical details above still apply and are still load bearing. One correction to them:
`bpf_skb_change_head` zeroes the room it makes, so on an L3-only device the MAC is already fresh —
but the *ethertype* must still be written, or `eth_type_trans` reads a zero as an 802.3 length and
the frame never reaches the IPv6 handler. On an Ethernet-framed device nothing is zeroed for us, so
both halves are written unconditionally.

`netif_is_l3_master` is a third escape: enslaving the interface to a VRF also skips the check. Not
taken — it means creating and owning a second interface, where the redirect needs none.

### Nothing polls any more, and the last hook needed the verifier consulted

The listener feed and the network-change detector were both 250ms polls. Replacing them turned up
one rule worth recording, in `__sock_filter_check_attach_type`:

| Field | Readable under |
|---|---|
| `bound_dev_if`, `mark`, `priority` | `SOCK_CREATE`, `SOCK_RELEASE` |
| `src_ip4` | `POST_BIND4` |
| `src_ip6` | `POST_BIND6` |
| **`src_port`** | **`POST_BIND4` and `POST_BIND6` only** |

So `cgroup/sock_release` cannot filter by port — the program is rejected at load time with
`Permission denied`, pointing at the field access. It therefore wakes on every UDP socket closing
rather than only the managed range. That is the right trade: the alternative is a served UDP port
that stays advertised after its server is gone, which looks exactly like a hang.

Four hooks are needed because none covers both protocols. `sock/inet_sock_set_state` is TCP-only,
and `post_bind` fires *before* `listen()`, so a TCP wakeup there would always scan too early.

Measured: **zero feed wakeups across five idle seconds**, where the poll it replaced would have
scanned twenty times.

**The hooks fire before the kernel has published the change**, and this cost a test cycle to find.
`inet_csk_listen_start` says so itself:

```c
	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */
	inet_sk_state_store(sk, TCP_LISTEN);   /* the tracepoint fires in here */
	err = sk->sk_prot->get_port(sk, inet->inet_num);
	...
		err = sk->sk_prot->hash(sk);       /* only now is it in /proc/net/tcp */
```

`inet_sk_state_store` calls the tracepoint *before* its `smp_store_release`, and the socket is
hashed later still — so a scan triggered by the wakeup is guaranteed to run too early, and nothing
further arrives to correct it. The listener is then never advertised.

It presented as a kernel-version difference rather than a race: identical code passed on 6.18 and
failed on 7.1, because the wakeup path happened to be slower than the hash on one and not the
other. A single appear/vanish cycle is not enough to catch it; the suite now does eight.

The fix is one re-read fifty milliseconds after any wakeup. That is not a poll — with nothing
happening there are no wakeups and so no re-reads — and it closes the same window in the other
direction, where a socket that has left `LISTEN` is still in the table when the scan runs.

The tracepoint's field offsets are read from `/sys/kernel/tracing/events/sock/inet_sock_set_state/format`
at load time rather than written into the program. The layout is stable in practice, but it is not
ABI, and the failure mode of getting it wrong is a feed that goes quiet rather than one that errors.

For network changes, netlink now says *when* to look while the address and route snapshots still
say *whether* anything mattered — so `needle` coming up, which is a change we made ourselves, still
produces no wakeup. Reading each message's type (and nothing else) is enough to report which of a
link, an address or a route moved, so the log line names the cause instead of guessing.

Suspend detection rides on the heartbeat rather than a timer of its own. It fires at least every
thirty seconds, and nothing is in flight across a suspend anyway.

### Checksums survive everything tested

- **200MB TCP transfer**: 209715200 bytes received, sha256 identical. This is the GSO test — the
  server writes megabytes on a 65536-MTU loopback socket and the kernel segments them for the
  transport after the rewrite.
- **UDP larger than the MTU**: a payload of 4× MTU echoed byte-identically, with 4 non-first
  fragments counted inbound, so the fragment path is genuinely exercised.
- **IPv4 UDP with a zero checksum**: the datagram still arrives. If the fixup had computed a real
  checksum over the zero field the receiver would have dropped it, so a successful echo is the
  assertion.

The fixups that make this work: `bpf_l3_csum_replace` for the IP header, `bpf_l4_csum_replace` with
`BPF_F_PSEUDO_HDR` for TCP and UDP, plus `BPF_F_MARK_MANGLED_0` on UDP so a zero checksum stays
zero.

### The fragment trap is real, and the plan's warning was right

tc ingress runs before IP reassembly, so a large UDP datagram arrives as several fragments and only
the first carries a UDP header. The program therefore has to:

- gate on the address, not the port, for later fragments — there is no port to read
- fix only the IP checksum on later fragments, and skip the L4 fixup entirely

Getting that backwards corrupts large datagrams while small ones work perfectly, which is exactly
the kind of bug that survives to production. The 4 non-first fragments counted on both transports
confirm the path is covered rather than merely written.

### WireGuard changed nothing that mattered

Phase 4 is Phase 3 with one variable swapped, and every assertion passed unchanged.

| | ethernet | wireguard |
|---|---|---|
| Device | `eth1`, ARPHRD_ETHER | `wg0`, `link/none` (ARPHRD_NONE) |
| MTU | 1500 | 1420 |
| L3 offset | 14 | 0 |
| Negotiated MSS | 1448 | 1368 |

The L2 boundary the plan flagged as a hazard is handled by reading `/sys/class/net/<iface>/type` at
load time and putting the offset in a map. One program serves both device classes; nothing needed a
second code path.

**MSS falls out correctly with no clamping.** The desktop's server socket is on loopback with an MTU
of 65536, but it sends 1368-byte segments over the tunnel, because the client's SYN advertises
against its own route. This was a prediction in the design conversation and is now measured.

---

# The system, assembled

Everything above proves a mechanism. `tests/endtoend.nix` is the first test where both halves run
together, and it is the one that proves a *product*: `curl localhost:8080` on the laptop reaching a
dev server bound to `127.0.0.1:8080` on the desktop, with nothing in the test ever naming the
desktop's address.

```
client was told 127.0.0.1:8080; server was told 127.0.0.1
desktop kernel view: 127.0.0.1:8080     10.7.0.1:42630
laptop kernel view:   10.7.0.1:42630     10.7.0.2:8080
```

Both applications believe they are on loopback; both kernels record the truth. A laptop-local
listener still wins, removing it hands the port back, UDP and a 200MB transfer both survive the
full chain, and a port the desktop does not serve returns `ECONNREFUSED` rather than hanging —
which confirms on the assembled system what Phase 3 implied: **the listener feed is a latency
optimisation, not a correctness requirement.**

# The control plane

Plain TCP over the tunnel, length-delimited postcard frames. WireGuard authenticates it and the
peer's identity is its tunnel source address, so there is no TLS, no certificate and no token.

Its one load-bearing job is liveness. Measured behaviour:

- The bridge starts **disabled** and stays that way until the desktop answers. Before that,
  `localhost:8080` behaves exactly as if needlecast were not installed.
- Bringing the desktop up enables the bridge on its own, with no restart.
- A port appearing on the desktop becomes usable within about a second; a port disappearing stops
  being forwarded.
- Killing the sleeve disables the bridge and **clears** the listener map — asserted to be empty,
  because a stale set is worse than none.
- The bridge reconnects on its own when the desktop returns.

Two things worth recording because they were not obvious:

**Ping must be on its own timer.** The first implementation read from the socket and only pinged
after a read returned. With a steady listener set neither side had anything to say, so both blocked
until the liveness timeout and the connection died every three seconds, forever. The fix is a short
socket read timeout (250ms) treated as routine, with ping and liveness on independent deadlines.

**The `TCP_SYNCNT` cap is real and measurable.** Wired into `connect4`, it applies to every
rewritten socket and only to rewritten sockets — 200 connections in the churn test produced 200
`setsockopt_ok` and zero errors. With the desktop's link down:

| `--syncnt` | time to fail |
|---|---|
| 1 | 3s |
| 4 | 36s |
| uncapped | ~2 minutes |

The knob visibly moves the deadline, which is what proves the cap is what bounds it rather than
something else timing out. The default of 2 gives a few seconds.

**The control connection is never itself forwarded**, and both halves of that are asserted: the
laptop's `connect4` declines it as non-loopback, and the desktop's tc ingress skips it as out of
range (visible as a rising `tc_ingress.port_out_of_range` while the heartbeat runs). If either
failed the control plane would be forwarding itself.

# Hostile cases

`tests/hostile.nix` is the regression suite. Everything in it is a way the system could be wrong
without any happy-path test noticing.

**Local priority.** An in-flight connection keeps flowing to the desktop when a local program takes
the port — established connections are never re-evaluated — while the *next* connection goes local.
Binding a port the bridge is serving always succeeds, because the bridge never holds it. Reversion
when the local program exits is automatic. A wildcard `0.0.0.0` bind wins the same way.

**Clean failure.** Killing the daemon drops the `bpf_link`s: `bpftool prog show` reports **zero**
`cgroup_sock_addr` programs afterwards, and behaviour is stock. A port neither side serves, and a
sleeve that dies, both give `ECONNREFUSED` rather than a hang.

**Non-interference.** Ports outside the managed range, and non-loopback destinations, are never
touched — asserted on both the outcome and the counter that says why.

**Protocol fidelity.** Half-close works: a client that shuts down its write side still receives
what the server sends afterwards. An abortive close disturbs nothing. A connection idle for 40
seconds is still established, which follows from there being no per-connection state anywhere but
is worth asserting in case an optimisation ever introduces some. `getpeername()` reports the
original address throughout.

**Load.** 200 sequential connections all complete, producing exactly 200 rewrites and 200
`setsockopt_ok` — no leak, no double-count. 50 simultaneous connections all complete.

Two test-design notes, both cases of a test failing for its own reasons rather than the system's,
which is worse than having no test:

- The first version of the load cases shared a server that held connections open for five minutes,
  so 250 connections pinned 250 threads. The holding server now has its own port.
- The probe's listen backlog was 16, so 50 simultaneous connections overflowed it and the test
  measured the harness rather than needlecast. It is now 256.

A third: counter assertions are only meaningful while the bridge is enabled. If the heartbeat
blips, `connect4` records `disabled` and every other branch goes uncounted, so the counter-based
subtests wait for `enabled=1` first. This showed up as a failure on one kernel and not the other,
which is exactly how a timing flake disguises itself as a kernel difference.

---

# The real build

Everything above proves a mechanism with the harness doing the setup. This is what changed when the
daemon started doing its own.

### The identity needs no pairing step, and that is checkable

Both keypairs come from `HKDF-SHA256(secret, "needlecast {server,client} key v1")`, so each machine
computes both and keeps a different one. Verified three ways rather than assumed:

- against an independent HKDF-SHA256 implementation,
- against the real `wg pubkey`, which is what proves X25519 clamping here matches WireGuard's,
- and in `tests/transport.nix`, which asserts the interface carries exactly the derived key.

```
$ needlecast keys ./secret
server ZVnbvcoGI3M2tQwGjUgMjlpUh7hRAZ6ve0/6iCJ0Y3Y=
client quNwuLJbIui3Quc9cqyXZEbtE22/YzLyou6PbbhKw1I=
```

Running that on both machines is a one-command check for the failure that would otherwise present
only as a handshake that never completes.

### Replacing a leftover interface beats adopting it

`create_interface` in `defguard_wireguard_rs` already swallows `EEXIST`, so adoption is free — but
it adopts whatever state the crash left, including a link someone downed and a stale peer set.
needlecast removes and recreates instead. It costs one handshake, it is deterministic, and the
interface is ours alone so nothing else can be disturbed by it. `tests/resilience.nix` kills each
half with `SIGKILL`, asserts the interface survived, and asserts the restart recovers.

### The endpoint really does have to be re-resolved

The `wg-quick` footgun, exercised by moving the peer's name to a dead address and back. The tunnel
stays down for as long as the name is wrong and recovers on its own when it is fixed — which is
what makes the recovery attributable to re-resolution rather than to ordinary retrying.

One detail fell out of that test: the NixOS framework publishes both an A and an AAAA for each
machine, and `getent hosts` answers with the v6 one. needlecast prefers the A record, because the
tunnel's own addressing is v4-only and a machine that publishes an AAAA it cannot be reached over
would otherwise leave the handshake failing with nothing to point at.

### The version check cannot be a postcard message

Postcard is non-self-describing, so a frame from a different schema decodes as *something* rather
than failing. A version field inside the first message is therefore unreadable exactly when it
matters. The handshake is eight raw bytes — `NDLC` plus a big-endian version — ahead of any framing,
and both sides send before either compares, so each can name the other's version in its error.

Exit code 78 (`EX_CONFIG`) on mismatch, which `nix/module.nix` names in
`RestartPreventExitStatus=` so the failure is loud and *stationary* rather than a crash loop.

### The firewall was a real gap the POC could not have found

Every POC suite ran with the firewall off. With it on, the server drops both the control connection
and the forwarded SYNs — inbound-initiated, so conntrack's `RELATED,ESTABLISHED` accept does not
help. Something has to open them.

The first attempt got this wrong twice, and both mistakes are worth keeping:

**Hand-written `iptables` and `nftables` rules, branched on which backend was enabled.** Unnecessary:
`networking.firewall.interfaces.<iface>.allowedTCPPortRanges` says the same thing in ordinary
options, works whichever backend you run, and translates to one sentence for a machine that is not
NixOS.

**And the rule it wrote was a hole.** It matched on destination address:

```
-A nixos-fw -d 127.0.0.0/8 -i needle -j nixos-fw-accept
```

which accepts *any* port on the tunnel interface so long as the destination is loopback. tc ingress
only rewrites packets addressed to the tunnel address on a port in the managed range — so a peer
crafting a packet addressed straight to `127.0.0.1:5432` would have been accepted by that rule and
delivered by `route_localnet`, reaching a database the range was supposed to keep out of reach. The
rule written to preserve "the range is the only limit" was the thing that broke it.

Matching on **port** instead is both simpler and strictly tighter. Ports are never translated, so
the destination port of a forwarded packet is the one the client asked for, and the managed range is
exactly the right filter:

```nix
networking.firewall.interfaces.needle = {
  allowedTCPPorts = [ controlPort ];
  allowedTCPPortRanges = [ range ];
  allowedUDPPortRanges = [ range ];
};
```

`tests/module.nix` asserts the negative directly: a service bound to `0.0.0.0` on a port outside the
range is not reachable over the tunnel. Without that, `trustedInterfaces = [ "needle" ]` would have
passed every other assertion in the file.

### The adaptive heartbeat is measurable rather than theoretical

One packet per second while `/proc/net/tcp` shows a flow to the peer, one per thirty seconds when it
does not. The liveness deadline is three intervals, so it tightens and relaxes with it — and the
one ordering hazard, that relaxing the interval must not retroactively expire a healthy connection,
is unit tested rather than argued.

The server's own idle timeout is two minutes, a generous multiple of the slowest heartbeat.
`tests/resilience.nix` `SIGSTOP`s the client and watches the server close the stalled connection,
which is the case that would otherwise be reaped only by TCP keepalive's two-hour default.

### The SYN cap was on one path out of three

`TCP_SYNCNT` was applied in `decide_v4` and nowhere else. That is wrong twice over, and both halves
showed up only once the client stopped being a test harness:

- **A dual-stack program asking for `localhost` never reaches `connect4`.** It gets
  `::ffff:127.0.0.1` and arrives in `connect6`, so exactly the programs most likely to be used —
  anything on a runtime that prefers `AF_INET6` sockets — were getting the stock two-minute hang
  when the server vanished between heartbeats.
- **`TCP_SYNCNT` is meaningless on a UDP socket.** `sendmsg4` was calling it per datagram, so
  `setsockopt_err` climbed steadily during any UDP traffic and would have buried a real failure.

Both are now asserted rather than assumed: `tests/laptop.nix` checks that a mapped-v6 rewrite gets
exactly one `setsockopt_ok`, and that an unconnected UDP datagram gets neither an ok nor an err.

### Pure logic moved where it could be tested

The BPF crate only builds for `bpfel-unknown-none` and cannot run a test. Every predicate that needs
no kernel context — the loopback tests, IPv4-mapped detection, the fragment test, header offsets,
the counter index arithmetic — now lives in `crates/common/src/net.rs` and is unit tested on the
host. Two of those have a wrong answer that corrupts only large or only dual-stack traffic, which is
precisely the kind of bug that survives to production.

---

# Toolchain

Three planned dependencies turned out to be unnecessary. PLAN.md called for `fenix` or
`rust-overlay`, `crane`, and `-Z build-std=core`. None of it is needed.

**nixpkgs' stable rustc ships a prebuilt `bpfel-unknown-none` target.** `libcore`, `liballoc` and
`libcompiler_builtins` are all under `$(rustc --print sysroot)/lib/rustlib/`. That deletes
`build-std`, and with it the vendoring problem that was the reason to reach for crane.

**aya-ebpf needs exactly one nightly feature** (`asm_experimental_arch`). `RUSTC_BOOTSTRAP=1` in
`crates/ebpf/.cargo/config.toml` unlocks it. This is a deliberate trade: nixpkgs' `bpf-linker` is built
against the same LLVM as nixpkgs' rustc, and a fenix nightly would break that pairing and drag
`build-std` back in to compile `core` for a target it does not ship.

So the flake gained one package, `bpf-linker`, and nothing else. Both derivations are plain
`stdenv.mkDerivation` plus `rustPlatform.importCargoLock`, with no extra flake inputs.

One nix gotcha: `rustPlatform.cargoSetupHook` preserves `crates/ebpf/.cargo/config.toml` rather than
replacing it, so setting `CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS` on the derivation *added* a
second `--btf` and bpf-linker rejected the duplicate. Let the config file own the rustflags.

---

# Aya traps

### Use `aya::include_bytes_aligned!`, not `include_bytes!`

Plain `include_bytes!` yields alignment 1, but the `object` crate parses the ELF header zero-copy
and needs it aligned. Whether that works depends on where the linker put the array, so it fails
*intermittently* — two builds of identical source produced one working and one failing binary.

Aya ships `include_bytes_aligned!` for precisely this, wrapping the bytes in a `repr(align(32))`
struct.

The cause was confirmed at the time by copying the same bytes to a deliberately odd address and
reproducing the *exact* error, which is what turned "we added alignment and it stopped failing"
into an identified cause:

```
misaligned_parse=failed
misaligned_error=ElfError(Error("Invalid ELF header size or alignment"))
```

That demonstration was a `dev` subcommand and two VM subtests. It is gone: it re-proved a property
of the `object` crate on every run rather than anything about needlecast. What remains is the guard
that matters — `assert_object_aligned()` runs before every load, and a unit test asserts the
embedded object is aligned.

The error is hard to diagnose because `EbpfError`'s Display collapses
`ElfError(object::read::Error)` to `error parsing ELF data` — the inner cause is invisible because
`ParseError::ElfError` does not declare its field as a `#[source]`. Reaching for `{:?}` on the raw
`EbpfError` is what made it diagnosable.

### `CgroupAttachMode::AllowMultiple` is unusable with `bpf_link`

On kernels ≥ 5.7 aya's `CgroupSockAddr::attach` takes the `bpf_link_create` path.
`CgroupAttachMode::AllowMultiple` maps to `BPF_F_ALLOW_MULTI`, a `BPF_PROG_ATTACH` flag that
`bpf_link_create` rejects with `EINVAL`, surfacing as an unexplained
`` `bpf_link_create` failed: Invalid argument (os error 22) ``.

Use `CgroupAttachMode::Single`, which maps to flags 0. Despite the name it does not restrict you to
one program: BPF links are inherently multi-attach, and the tests attach two `connect4` programs to
the same cgroup simultaneously without complaint.

### No safe wrappers for the helpers that matter

`bpf_sk_lookup_tcp`, `bpf_sk_lookup_udp`, `bpf_sk_release`, `bpf_get_netns_cookie` and
`bpf_setsockopt` are all raw `unsafe` bindings re-exported from `aya-ebpf-bindings`. All eight
`cgroup_sock_addr` attach types are supported by the `#[cgroup_sock_addr]` macro, and
`#[classifier]` covers the tc programs.

---

# Container and network namespace isolation

`tests/isolation.nix` covers the hazard the design conversation raised: programs attached to the
root cgroup also fire for processes in containers, which are in your cgroup tree but not your
network namespace.

Three mechanisms, all real rather than simulated:

- a **podman container** on `--network=none`, from an image built locally with `dockerTools` so the
  test never touches a registry
- a **manually created persistent netns** (`ip netns add`) bound to a systemd service through
  `NetworkNamespacePath=`
- a systemd service with **`PrivateNetwork=yes`**

For each: traffic to a port with a listener inside the namespace reaches it untouched, and traffic
to an unbound port fails with a clean `ECONNREFUSED` rather than being redirected. The host is
asserted to still be forwarding at the same time, so the suite cannot be satisfied by a program that
has simply stopped working.

Two things this measured that were not obvious:

**`bpf_sk_lookup_tcp` resolves in the caller's namespace, not the loader's.** With
`BPF_F_CURRENT_NETNS`, a container connecting to a port its own namespace is listening on finds that
socket and is left alone — even with the netns guard disabled. So the guard is not what protects
container-local traffic that has a listener; the socket lookup already does.

**The guard protects the unbound case, and that case is a real break.** With `--no-netns-guard`, a
container connecting to a port nothing is listening on gets rewritten to the tunnel address, which
does not exist in its namespace, and the application sees `ENETUNREACH` instead of `ECONNREFUSED`.

That breakage is asserted as a **negative control**. Without it, every other assertion in the file
would still pass if the guard were deleted, because they would all be satisfied by a program that
never rewrites anything.

---

# Test harness notes

**Wait on real readiness, not on side effects.** The first version waited for a pinned map to
appear, which happens during load — before any attach. A failing attach therefore looked like a
timeout with no diagnostics, and the map pins survived the crashed process so the wait could even
succeed against a dead loader. Both loaders now write a ready file only after every attach and
config write succeeded, and the tests dump the service journal when that wait times out.

**Counters beat `bpf_printk`.** Pinned counter arrays indexed by `(program, event)` let scenarios
assert on which branch the program took, not merely on the observable outcome. Several assertions
distinguish "the connection went local because a listener was found" from "the connection went local
because the port was out of range", which an end-to-end check alone cannot. Assert on *deltas*,
since counters accumulate across scenarios.

**`bpftool cgroup show` does not list link-attached programs** on these kernels, so it is not a
usable attach assertion. The ready file lists what actually attached.

**Both ends of a TCP connection must hold it open** to observe it in `ss`. A server that sends and
closes leaves the desktop in `FIN_WAIT`, not `ESTABLISHED`, and the assertion times out with no hint
as to why.

**Do not guess NixOS test vlan addressing.** The framework assigns `192.168.1.x` in an order that is
not the order nodes are declared — `laptop` got `.2`, so a hardcoded WireGuard endpoint pointed the
node at itself and the handshake silently never completed. Machine *names* resolve through
`/etc/hosts`; use `endpoint = "desktop:51820"`.

---

# What is in the repo

Every crate lives under `crates/`. `crates/ebpf` is its own cargo workspace rather than a member of
the root one: it builds for `bpfel-unknown-none`, so it needs its own lockfile and its own
`.cargo/config.toml`, and an empty `[workspace]` table is how a crate opts out of the enclosing one.

Each BPF program is self-contained in its own file; the plumbing they share is in named modules,
and every predicate that needs no kernel context lives in `crates/common/src/net.rs` where it can
be unit tested on the host.

```
crates/ebpf/src/main.rs          module declarations and the panic handler, nothing else
crates/ebpf/src/maps.rs          every map, declared once, plus the counter helpers
crates/ebpf/src/sock.rs          raw `cgroup_sock_addr` access; the unsafe helper bindings live here
crates/ebpf/src/packet.rs        IPv4 parsing and rewriting from a tc context: L3 offset, fragments, csums
crates/ebpf/src/decide.rs        the client's decision policy, shared by connect and sendmsg
crates/ebpf/src/restore.rs       the client's undo policy, shared by getpeername and recvmsg
crates/ebpf/src/connect.rs       connect4, connect6
crates/ebpf/src/sendmsg.rs       sendmsg4, sendmsg6
crates/ebpf/src/getpeername.rs   getpeername4, getpeername6
crates/ebpf/src/recvmsg.rs       recvmsg4, recvmsg6
crates/ebpf/src/tc_ingress.rs    tc_ingress
crates/ebpf/src/tc_egress.rs     tc_egress
crates/ebpf/src/sleeve_peer.rs   sleeve_getpeername4
crates/ebpf/src/syncnt_probe.rs  connect4_syncnt_probe, an isolated capability probe

crates/common/src/net.rs    loopback and fragment predicates, header offsets; unit tested
crates/common/src/lib.rs    Config, SleeveConfig, counter indices; no_std, shared both directions
crates/common/src/proto.rs  the wire protocol, the magic, and the version-mismatch exit code

crates/needlecast/src/main.rs       the CLI: server, client, status, keys, dev
crates/needlecast/src/identity.rs   HKDF-SHA256 derivation of both keypairs from one secret
crates/needlecast/src/transport.rs  the `needle` interface: create, configure, re-resolve, remove
crates/needlecast/src/server.rs     the datapath half
crates/needlecast/src/client.rs     the decision half and its state machine
crates/needlecast/src/control.rs    liveness, the listener feed, the adaptive heartbeat
crates/needlecast/src/status.rs     kernel and filesystem state, no IPC
crates/needlecast/src/wake.rs       resume and network-change detection
crates/needlecast/src/shutdown.rs   signal handling, so a clean exit removes the interface
crates/needlecast/src/harness.rs    test scaffolding, only with `--features testing`
crates/needlecast/tests/handshake.rs  the version preamble, from both directions
crates/needlecast/tests/vm.rs         every VM suite, as a test nextest can run

nix/ebpf.nix         BPF object derivation
nix/needlecast.nix   userspace derivation; `testing ? false` selects the two builds
nix/module.nix       services.needlecast.{server,client}
tests/lib/scenarios.nix  the shared node definition and the Python helpers every suite uses
tests/lib/probe.nix      socket probe: which server answered, what getpeername says, bulk and
                         large-datagram modes, --gate for mid-flow changes
tests/lib/transport.nix  ethernet and WireGuard link definitions, for the harness suites only
```

---

# Still open

- **A bind/connect race** in a tight loop from two processes.

**Smaller:**

- A server that learns its peer outside the socket API — parsing `/proc/net/tcp`, or a sidecar
  reading `ss` — sees the client's tunnel address. Nothing in the wire path changes, by design.
- Only `--network=none` podman containers are covered.
- Checksum correctness is asserted functionally, through hash-identical transfers, rather than by
  inspecting which `ip_summed` states were exercised.

---

# What only two real machines can prove

Everything above was measured in a VM. These cannot be, and are listed so they are a checklist
rather than folklore. None is a known problem; each is a claim the suite does not reach.

### Suspend and resume

The one with a real chance of being wrong, because the whole mechanism is inferred from two clocks
rather than from an event.

```
# on the laptop, connected and idle
needlecast status --role client        # note `handshake=` and `state=connected`
# close the lid, wait past two minutes, reopen
journalctl -u needlecast-client -f
```

Expect `resumed from suspend, reconnecting now` within a second or two of the lid opening, and
`state=connected` shortly after. The failure to watch for is *silence*: `wake::Watch` reads
`CLOCK_BOOTTIME − CLOCK_MONOTONIC`, and if that gap does not move across a real suspend the daemon
waits out its backoff instead — up to five seconds, which is survivable, and then a full liveness
deadline if the socket is also dead, which is not.

A related unit test exists (`the_suspend_gap_holds_still_while_the_machine_is_awake`) and a related
bug was found by it: reading `CLOCK_BOOTTIME` *first* made the subtraction underflow on a machine
that had never suspended, and `saturating_sub` reported a flat zero forever. That is fixed, but it
is exactly the class of thing only a real suspend confirms.

### Roaming between real networks

`resilience` fakes a moved peer with `/etc/hosts`. Only a real move exercises WireGuard's own
roaming, where the *server* sees the client arrive from a new address without anything being
re-resolved.

```
# laptop connected on wifi, then move to a different network entirely
needlecast status --role client        # peer_endpoint= should follow
curl http://localhost:8080             # should keep working, or recover within ~5s
```

Two distinct paths are in play and the test cannot tell them apart: needlecast re-resolving the
server's name, and WireGuard roaming the peer when a handshake arrives from elsewhere. On a real
move both happen.

### A two-machine install from the module

The VM suite installs from the module, but on machines that were created together. Worth doing once
by hand:

```
head -c 32 /dev/urandom | base64 > secret && chmod 600 secret
# copy to both machines by hand, mode 600, then set services.needlecast.{server,client}
needlecast keys /path/to/secret        # the two public keys, on both machines
wg show needle                         # must agree with them
```

The prerequisite the tests never have to satisfy: **the client must be able to reach the server's
`listenPort` (47654/udp)**. Behind NAT that means a port forward. Nothing in needlecast performs
NAT traversal.

### Long-running stability

VM suites run for minutes. Nothing has been observed over days: no memory growth measurement, no
check that the counters stay sane after millions of connections, no confirmation that the tunnel
survives a DHCP lease renewal or a sleeping switch port.

### Battery cost of the idle heartbeat

The design argues that 30s while idle is cheap and 1s while a flow is open is worth it. Never
measured. `powertop` or `powerstat` on a laptop with the client running and no traffic, against the
same laptop with it stopped, would settle it.
