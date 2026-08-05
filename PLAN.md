# needlecast: the plan, and what became of it

The record of how this got built, kept as a plan rather than rewritten as a summary — the crossed-
off items are the useful part.

Phases 1 through 9 were proofs of concept: every item existed to answer a kernel-behaviour question
the architecture in [initial_design_conversation.md](initial_design_conversation.md) assumed but
nobody had observed. Phase 10 is the real build. All of them are done; what remains is listed at
the end of Phase 10.

What was measured rather than assumed is in [FINDINGS.md](FINDINGS.md); the requirements and
decisions above the kernel are in [DESIGN.md](DESIGN.md).

## What the design already settled

- Laptop decides at `connect()` time with `cgroup/connect4`, using a live `bpf_sk_lookup_tcp()`
  so a local listener always wins with no cached state.
- Laptop rewrites the destination straight to the desktop's WireGuard address. No rendezvous
  socket, no userspace proxy, no correlation maps.
- Desktop rewrites addresses in tc programs so a server bound to `127.0.0.1` receives the
  connection and believes its peer is loopback.
- Transport is a self-managed WireGuard interface. Neither daemon ever touches a byte.
- A plain TCP control connection over the tunnel carries liveness, one-shot negotiation, and the
  desktop's listener set. WireGuard authenticates it, so there is no TLS and no token.
- v1 covers TCP and UDP. UDP is in scope because the WireGuard datapath makes it the same design
  as TCP with a different socket type — genuinely UDP end to end, no framing, no size ceiling, no
  nested congestion control. The desktop programs are L4-agnostic beyond checksums and the port
  test, so UDP costs two extra laptop-side hooks and nothing else.
- v1 is laptop-originated only, loopback destinations in a configured port range only.

## The questions the POCs must answer

Ranked by blast radius if the answer is no.

| # | Question | Status | Fallback if false |
|---|---|---|---|
| 1 | Can a tc program on `wg0` get a rewritten packet delivered to a server bound to `127.0.0.1`? | **yes**, verified | Whole in-kernel datapath dies; revert to a userspace sleeve proxy on the desktop |
| 2 | Can a reply routed to `lo` be caught on lo egress and redirected into `wg0`'s transmit path, with allowed-ips matching? | open — Rung A needs no lo redirect, so this is now scoped to Rung B | Drop the source rewrite; accept that the dev server sees peer `10.7.0.1` |
| 3 | Is `bpf_sk_lookup_tcp()` callable from `cgroup_sock_addr`? | **yes**, verified | Local-wins stops being exact; feed a listener map from an `inet_sock_set_state` tracepoint |
| 4 | Does `connect4` accept rewriting a loopback destination to a non-loopback address, and does routing then select `wg0`? | **yes**, verified against a non-loopback local address | Laptop needs the rendezvous socket plus the `sock_ops` cookie handoff that this design deleted |
| 5 | Do checksums survive the rewrite across `CHECKSUM_PARTIAL` on lo, post-decrypt from WireGuard, and GSO super-packets? | **yes**, verified — 200MB hash-identical, oversized UDP byte-identical | Silent corruption — no clean fallback, must be solved |
| 6 | Does `bpf_sk_lookup_udp()` work the same way from `sendmsg4`, and does `recvmsg4` let you restore the source address? | **yes**, verified | UDP drops back to v2 and the laptop needs a different correlation trick |
| 7 | Which hook fires for connected versus unconnected UDP sockets — `connect4`, `sendmsg4`, or both? | **`connect4` only** for connected, `sendmsg4` only for unconnected | Only affects where the decision code lives, not whether the design works |
| 8 | Is `bpf_setsockopt(TCP_SYNCNT)` permitted in `cgroup_sock_addr`? | **yes**, accepted by the verifier and returns 0 at runtime | The SYN-timeout window after the desktop vanishes stays at ~2 minutes |

All of these except question 2 are settled — see [FINDINGS.md](FINDINGS.md). Question 2 now applies
only to Rung B, since Rung A's reply routes out the transport interface without any redirect.

## Watch for the L2 boundary

`wg0` is `ARPHRD_NONE` — packets there carry no link-layer header. `lo` is Ethernet-framed;
`tcpdump -i lo` shows 14-byte frames with zero MAC addresses. Every wg0 to lo redirect crosses
that boundary in both directions.

The kernel's `__bpf_redirect` does some header fixup based on target device type, but whether it
covers the L3-source into L2-target ingress direction is unverified. Budget for pushing a dummy
Ethernet header with `bpf_skb_change_head(skb, 14, 0)` on the wg0 to lo path and stripping it
with `bpf_skb_adjust_room(skb, -14, BPF_ADJ_ROOM_MAC, 0)` on the way back. Establish this in
Phase 3, not Phase 7.

## Watch for UDP fragments

tc ingress runs before IP reassembly, so a UDP datagram larger than the path MTU arrives as
several fragments and each one hits your program separately. Only the first fragment carries a
UDP header.

Two consequences for the desktop programs. Non-first fragments have no port to range-check, so
the decision has to key on the address alone — which is fine, because the address is the peer
identity in this design, but it means the port test cannot be the first thing you branch on.
And the L4 checksum fixup applies only to the first fragment; every other fragment needs the IP
header rewritten and the IP checksum fixed with no L4 work at all. Getting this backwards
corrupts large datagrams while leaving small ones working perfectly, which is a miserable bug to
find later.

## Watch for UDP's different local-wins semantics

TCP's rule is that established connections are never re-evaluated — a live session keeps flowing
to the desktop after a local program takes the port, and only new connections go local. UDP has
no connections, so an unconnected socket sending through `sendmsg4` re-evaluates on every packet.
A local listener appearing mid-flow will silently redirect the next datagram.

That is arguably the correct behaviour, but it is a different behaviour, and it needs to be a
deliberate decision with a test asserting it rather than something discovered in use. Connected
UDP sockets decide once at `connect()` and behave like TCP.

## Build the datapath in three rungs

Do not start with the full invisible design. Each rung isolates a different variable.

**Rung A, no redirect.** tc ingress on `wg0` rewrites destination `10.7.0.2:P` to `127.0.0.1:P`,
leaves the source as `10.7.0.1`, returns `TC_ACT_OK`. The reply routes back out `wg0` naturally;
a tc egress program on `wg0` rewrites source `127.0.0.1` to `10.7.0.2`. No `bpf_redirect`, no L2
juggling, no lo programs. Needs `route_localnet=1` and probably `rp_filter=0` on wg0.

This is not the target design — the dev server sees a peer of `10.7.0.1` — but it proves the
rewrite, the checksum arithmetic, and local delivery in isolation. If Rung A fails, nothing above
it can work.

**Rung B, invisible peer.** Also rewrite the source to an address out of `127.71.0.0/16`. The
reply now routes to `lo`, so you need the lo egress program plus `bpf_redirect(wg0_ifindex)`.
This is where questions 2 and the L2 boundary land.

**Rung C, redirect inbound.** Replace Rung A's `TC_ACT_OK` with
`bpf_redirect(lo_ifindex, BPF_F_INGRESS)`. This is what escapes `route_localnet` and `rp_filter`
entirely — the packet re-enters at lo, where loopback addresses are unremarkable. Do it only
after B works, or you change two variables at once.

Run Rungs A and B over a plain veth pair before swapping in real WireGuard. A veth tells you
nothing about allowed-ips or L3 device types, but it does tell you whether your checksum
arithmetic is right, and that is the part most likely to be wrong.

---

## Phase 1: Stand up the build and test loop

Done. The toolchain turned out to be much simpler than planned — see
[FINDINGS.md](FINDINGS.md) for why fenix, crane and `-Z build-std` are all unnecessary.

- [x] ~~Add a nightly Rust toolchain via `fenix` or `rust-overlay`~~ — not needed. nixpkgs' stable
      rustc already ships a prebuilt `core`, `alloc` and `compiler_builtins` for
      `bpfel-unknown-none`, and `RUSTC_BOOTSTRAP=1` unlocks the single nightly feature aya-ebpf
      needs. That also keeps rustc's LLVM matched to nixpkgs' `bpf-linker`.
- [x] Add `pkgs.bpf-linker` to the devshell.
- [x] ~~Confirm `-Z build-std=core` works~~ — moot, `core` is prebuilt.
- [x] Create the workspace layout:
      - [x] `crates/ebpf/` — `no_std`, its own workspace, target `bpfel-unknown-none`
      - [x] `crates/common/` — `no_std`, map key and value types shared both ways
      - [x] `crates/poc/` — the loader plus a control CLI
      - [x] `nix/ebpf.nix` — derivation producing the `.o`
      - [x] `nix/poc.nix` — userspace binary, receiving the `.o` path via env var
      - [x] `tests/` — one `runNixOSTest` per POC
      - [x] `tests/lib/nodes.nix` — shared machine definition, parameterised by kernel
      - [x] `tests/lib/probe.nix` — the socket probe every scenario drives
      - [ ] `tests/lib/scenarios.nix` — parameterised scenarios. Deferred: Phase 2's assertions
            live inline in `tests/phase2.nix` because they exercise the POC's own counters, which
            the real daemon will not expose. Extract when Phase 9 starts, which is the first point
            where the same scenario has two implementations to run against.
- [x] Wire the object into userspace with
      `aya::include_bytes_aligned!(env!("NEEDLECAST_EBPF_OBJ"))`. Plain `include_bytes!` is
      misaligned for aya's ELF parser and fails intermittently — see FINDINGS.md.
- [x] Write a single-node `runNixOSTest` that loads the programs and asserts they attached.
      - [x] Run every suite on **6.18** (the target kernel) and on `linuxPackages_latest`. Each
            test asserts the kernel it booted. Results are identical on both.
      - [x] `tcpdump`, `iproute2`, `curl`, `python3`, `bpftool`, `socat` in
            `environment.systemPackages`
      - [ ] debugfs mounting for `bpf_printk` — not needed yet; the counter map has been a better
            debugging channel than `trace_pipe` because tests can assert on it.
- [x] Confirm the test kernel has BTF. Present, and the object carries `.BTF`/`.BTF.ext`.

## Phase 2: Verify the laptop decision path

Done, and every question it was meant to answer came back yes. Single-node VM test in
`tests/phase2.nix`, run with `nix build .#checks.x86_64-linux.phase2`. Full write-up in
[FINDINGS.md](FINDINGS.md).

- [x] Settle the aya API surface. There are **no safe wrappers** — `bpf_sk_lookup_tcp`,
      `bpf_sk_lookup_udp`, `bpf_sk_release`, `bpf_get_netns_cookie` and `bpf_setsockopt` are all
      raw `unsafe` bindings re-exported from `aya-ebpf-bindings`. All eight `cgroup_sock_addr`
      attach types are supported by the `#[cgroup_sock_addr]` macro.
- [x] `cgroup/connect4` with the enabled flag, netns cookie guard, loopback and port-range
      checks, live `bpf_sk_lookup_tcp`, and the rewrite.
- [x] `cgroup/getpeername4` undoing it.
- [x] Assert: with a local listener present, the connection lands locally and `getpeername()`
      reports `127.0.0.1:8080`.
- [x] Assert: with no local listener, the connection lands on the rewritten address and
      `getpeername()` still reports `127.0.0.1:8080`.
- [x] Assert: inside `ip netns exec`, nothing is rewritten.
- [x] Assert: clearing the enabled flag restores stock behaviour, including a clean
      `ECONNREFUSED`.
- [x] Mirror to `connect6` / `getpeername6` for `::1`, plus IPv4-mapped `::ffff:127.0.0.1`.
- [x] Confirm a laptop process bound to `0.0.0.0` is found by the socket lookup.
- [x] Check `bpf_setsockopt(TCP_SYNCNT)`. Accepted by the verifier, attaches, and returns 0 at
      runtime.

UDP hooks:

- [x] Determine which hook fires for connected versus unconnected UDP. **Connected sockets go
      through `connect4` and never reach `sendmsg4`; unconnected sockets go through `sendmsg4`
      only.** They are disjoint, so the two paths can share one decision function without
      double-counting.
- [x] `cgroup/sendmsg4` using `bpf_sk_lookup_udp`.
- [x] `cgroup/recvmsg4` restoring the source address on replies.
- [x] Assert: with a local UDP listener, datagrams go local.
- [x] Assert: with no local listener, datagrams are rewritten and `recvfrom()` still reports
      `127.0.0.1:8080`.
- [x] Assert: a connected UDP socket decides once and keeps its decision.
- [x] Mirror to `sendmsg6` / `recvmsg6`.
- [x] Assert an unconnected socket re-evaluates per datagram. One socket, two `sendto` calls with a
      local listener started in between: the first goes remote, the second goes local, and
      `recvmsg4` restores the source on both.
- [x] IPv6 UDP behavioural coverage for `sendmsg6` / `recvmsg6`.

## Phase 3: Verify the desktop delivery path

Done. Built as `tests/desktop.nix` over two nodes on plain ethernet rather than a veth pair, so
Phase 4 is the same test with one variable changed. Run with
`nix build .#checks.x86_64-linux.desktop-ethernet-6_18`.

- [x] Build Rung A: tc ingress rewriting the destination to `127.0.0.1:P`, returning `TC_ACT_OK`.
- [x] Build the matching tc egress program rewriting the source back.
- [x] Determine empirically which sysctls are actually required. Answer: **one**.
      - [x] `net.ipv4.conf.<if>.route_localnet` — required. With it off the SYN is dropped as
            martian, so the failure is a hung connect, not a clean error.
      - [x] `net.ipv4.conf.<if>.rp_filter` — **not** required. Strict mode works, because the source
            is the laptop's tunnel address, which is genuinely routable via that interface.
      - [x] `net.ipv4.conf.all.route_localnet` stays `0` throughout; the per-interface setting alone
            does the work.
- [x] Get the checksum fixups right:
      - [x] `bpf_l3_csum_replace` for the IPv4 header
      - [x] `bpf_l4_csum_replace` with `BPF_F_PSEUDO_HDR` for TCP and UDP
      - [x] `BPF_F_MARK_MANGLED_0` for IPv4 UDP, so a zero checksum stays zero
      - [ ] Log the incoming `skb->ip_summed` state on each path. Not done — correctness is
            asserted functionally instead, which is conclusive but does not reveal which states were
            exercised.
- [x] Assert the client reaches a server bound to `127.0.0.1`.
- [x] Assert `ss` on the desktop shows the local address you expect (`127.0.0.1:8081`), with the
      laptop's tunnel address as the peer — the known Rung A limitation, asserted rather than
      assumed.
- [x] Assert a 200MB transfer completes with a matching hash. This is the GSO test.
- [x] Assert a UDP echo round trip works, with the payload arriving byte-identical.
- [x] Assert a UDP datagram larger than the path MTU survives. Four non-first fragments counted
      inbound, so the fragment path is genuinely exercised.
- [x] Assert an IPv4 UDP datagram sent with a zero checksum still arrives.
- [ ] `tcpdump -vv` checksum inspection. Skipped deliberately: on `lo` and for locally generated
      packets, `CHECKSUM_PARTIAL` makes tcpdump report false "incorrect" verdicts, so it would be a
      flaky assertion. The hash-identical transfer is the real test.
- [ ] IPv6 on the desktop datapath. The tc programs count v6 packets and pass them through
      untouched; there is no v6 rewrite path yet.

## Phase 4: Swap in real WireGuard

Done, and it changed nothing that mattered. Same test file, `transport = "wireguard"`. Run with
`nix build .#checks.x86_64-linux.desktop-wireguard-6_18`.

- [x] Configure `wg0` declaratively with `networking.wireguard.interfaces.wg0` and keys hardcoded
      in `tests/lib/transport.nix`. Use machine *names* for the endpoint — the test framework's
      vlan address ordering is not the node declaration order.
- [x] Re-run every Phase 3 assertion with `wg0` in place of ethernet. All pass unchanged.
- [x] Confirm the L3 device type does not break the tc programs' header offsets. `wg0` reports
      `link/none`; reading `/sys/class/net/<iface>/type` at load time and putting the offset in a
      map means one program serves both device classes.
- [x] Confirm MSS lands correctly. 1368 over wg0's 1420 MTU versus 1448 over ethernet's 1500, with
      no clamping — the server's loopback socket segments for the tunnel because the client's SYN
      advertises against its own route.
- [x] Re-run the 200MB transfer against the GSO-to-1420 path.
- [x] Re-run the oversized UDP datagram against wg0's MTU.

## Phase 5: Make the peer address invisible

Done. The server is told `127.0.0.1` — byte-identical to a genuinely local connection — and nothing
on the desktop outside the transport interface is touched.

- [x] `cgroup/getpeername4` on the desktop reports the peer as `127.0.0.1`. The packet is left
      alone, so routing needs no help. Same mechanism the laptop already uses, run in reverse.
- [x] Gate it on `ctx->sk`: rewrite only when the socket's local address is `127.0.0.1`, its local
      port is in the managed range, and the peer is the paired laptop.
- [x] Assert the forwarded connection and a genuinely local one report the *same* address, so an
      exact `== 127.0.0.1` comparison cannot separate them.
- [x] Assert no route added, no `clsact` qdisc on `lo`, and `all`/`lo`/`default` `route_localnet`
      all still `0`.
- [x] Assert bulk transfer, UDP and oversized fragmented UDP still work.
- [x] ~~Rewrite the source into `127.71.0.0/16`~~ — implemented, measured, deleted. It needs the
      reply steered back out of loopback, which costs either a local-table route or a tc program on
      `lo`, and it forces a distinct peer address that is *almost* local rather than local.
- [x] ~~Add a tc egress program on `lo`~~ — never worked, and ruled out by interface ownership.
- [ ] `getpeername6` on the desktop, once the desktop datapath handles IPv6 at all.

## Phase 6: Redirect inbound and drop the sysctls — rejected

Implemented, measured, and removed. The premise was false: `bpf_redirect(lo, BPF_F_INGRESS)` moves
only the inbound `route_localnet` check to `lo`. The reply still leaves from `127.0.0.1` via the
transport interface and needs the sysctl there anyway, so the redirect costs **two** interfaces
where Rung A costs one — and the extra one is `lo`, which needlecast does not own.

- [x] Replace `TC_ACT_OK` with `bpf_redirect(lo_ifindex, BPF_F_INGRESS)`.
- [x] Measure what it requires. Works only with `lo` **and** the transport interface set, or with
      the system-wide `all`.
- [x] Confirm `route_localnet` is no longer needed. **It still is.** Phase rejected.
- [x] Record the two mechanical findings for future reference: an L3-only source device needs
      `bpf_skb_change_head(skb, 14, 0)`, and the link header must be *freshly zeroed* or
      `eth_type_trans` marks the frame `PACKET_OTHERHOST` and `ip_rcv` drops it.

Constraint this established: **only interfaces needlecast creates may be configured.** Rung A
satisfies it with a single `net.ipv4.conf.<wg-iface>.route_localnet=1`, which lives and dies with
the interface. Phase 5 should be reconsidered against the same constraint before it is built — its
tc egress program attaches to `lo`.

## Phase 7: Converge end to end

Done. `tests/endtoend.nix` is the first test in which both halves run together, and no assertion in
it ever names the desktop's address.

- [x] Point the laptop's `connect4` at the desktop's tunnel address.
- [x] Assert `localhost:8080` on the laptop reaches the desktop's dev server, port preserved.
- [x] Assert both applications believe they are on loopback while both kernels record the truth.
- [x] Assert a laptop-local listener still wins, and that removing it hands the port back.
- [x] Assert UDP, an oversized UDP datagram, and a 200MB transfer all survive the full chain.
- [x] Assert a port the desktop does not serve gives `ECONNREFUSED` rather than hanging — which
      confirms on the assembled system that the listener feed is an optimisation, not a
      correctness requirement.
- [x] Assert stopping the laptop bridge reverts everything.

## Phase 8: Build the control plane

Done. Plain TCP over the tunnel, length-delimited postcard. `crates/poc/src/control.rs` and
`crates/common/src/proto.rs`; `tests/control.nix` covers it.

- [x] Sleeve listens on the tunnel address at a fixed high port; laptop dials with backoff.
- [x] `Hello` / `Welcome`, `Ping` / `Pong`, `Listeners`, `Goodbye`.
- [x] State machine: reaching ready sets the enabled flag; any error clears it **first**, then
      clears the listener map, then backs off.
- [x] The bridge starts disabled and only enables once the desktop answers, so an unreachable
      desktop behaves exactly as if needlecast were not installed.
- [x] Listener feed: the sleeve enumerates its own listening sockets from `/proc/net/tcp{,6}` and
      `/proc/net/udp{,6}`, filters to the managed range, and publishes on change.
- [x] The laptop mirrors it into `DESKTOP_PORTS`, and **clears** it on disconnect.
- [x] Assert a port appearing becomes usable and a port disappearing stops being forwarded, with
      no restart.
- [x] Wire `TCP_SYNCNT` into `connect4`, applied to rewritten sockets only. Measured: `--syncnt 1`
      fails in 3s, `--syncnt 4` in 36s, uncapped about two minutes.
- [x] Assert the control connection is never itself forwarded, from both ends.
- [ ] Drive the listener feed from an `inet_sock_set_state` tracepoint instead of a 250ms poll, to
      shrink the window where a just-started desktop server is not yet reachable.
- [ ] Version-mismatch handling exists in the code but has no test.

## Phase 9: Build the hostile-case suite

Done, as `tests/hostile.nix`. Everything in it is a way the system could be wrong without any
happy-path test noticing.

**Local priority**

- [x] An in-flight connection keeps flowing to the desktop when a local program takes the port,
      while the next connection goes local.
- [x] Reversion when the local program exits.
- [x] `bind()` on a port the bridge is serving always succeeds.
- [x] A wildcard `0.0.0.0` bind wins the same way.

**Clean failure**

- [x] Daemon death drops the `bpf_link`s — `bpftool prog show` reports zero `cgroup_sock_addr`
      programs — and behaviour is stock.
- [x] A port neither side serves gives `ECONNREFUSED`.
- [x] A sleeve that dies disables the bridge rather than hanging it.

**Non-interference**

- [x] Ports outside the managed range are never touched.
- [x] Non-loopback destinations are never touched.
- [x] The control connection is never itself rewritten, asserted from both ends.
- [x] Containers and namespaces, in `tests/isolation.nix`, with a negative control.

**Protocol fidelity**

- [x] Half-close: a client that shuts down its write side still receives what follows.
- [x] Abortive close disturbs nothing else.
- [x] A connection idle for 40s is still established.
- [x] `getpeername()` reports the original address throughout.
- [x] An HTTP request through the bridge is served, Host header untouched.

**Load**

- [x] 200 sequential connections: all complete, exactly 200 rewrites, 200 `setsockopt_ok`.
- [x] 50 simultaneous connections all complete.

**Not covered**

- [x] Desktop reboots mid-flow — covered by `tests/resilience.nix`, as a crash and a clean stop.
- [x] A network change that makes WireGuard roam — `tests/resilience.nix` moves the peer's name to
      a dead address and back, which is the only exercise of the re-resolution path.
- [x] `tests/lib/scenarios.nix`, extracted once every product suite drove the same two commands.
- [ ] Laptop suspend and resume, end to end. The detector is unit tested; the VM cannot suspend.
- [ ] A bind/connect race in a tight loop from two processes.

## Phase 10: Everything above the kernel — done

The requirements and decisions live in [DESIGN.md](DESIGN.md). Every gap that document was written
to close is now built and under test. Two commands, one shared secret, and a tunnel needlecast
creates and owns:

```
needlecast server ./secret cesium.gio.ninja     # on the desktop
needlecast client ./secret cadmium.gio.ninja    # on the laptop
needlecast status
```

- [x] **The daemon owns its own WireGuard interface.** `crates/needlecast/src/transport.rs` over
      `defguard_wireguard_rs`: create-or-replace `needle`, address it from `198.18.0.0/15`, set the
      MTU, configure the peer with a `/32` allowed-ips, and remove it on a clean exit.
      `net.ipv4.conf.needle.route_localnet=1` on the server only.
- [x] **Endpoint re-resolution**, the `wg-quick` footgun: re-resolved on every reconnect attempt and
      every five minutes while connected, updated only when the answer changed.
- [x] **No pairing step.** Both keypairs are HKDF-SHA256 derived from one shared file, so neither
      side has anything the other lacks. Cross-checked against `wg pubkey`.
- [x] **A real daemon.** `server`, `client` and `status`; the experiment-per-subcommand surface is
      gone. What the suites still need to isolate one half lives behind the `testing` crate feature
      and cannot be expressed by the shipped binary.
- [x] **`needlecast status`**, reading kernel and filesystem state with no IPC, so it works when the
      daemon is wedged. Four states, each reached for real in `tests/status.nix`.
- [x] **Adaptive heartbeat**, resume and network-change detection, and a server-side idle timeout.
- [x] **A fatal, diagnosable version mismatch.** Eight raw bytes ahead of any postcard frame, so two
      builds with incompatible schemas can still name each other's version. Exit 78, which the
      module names in `RestartPreventExitStatus=`.
- [x] **A NixOS module**, `nix/module.nix`, with the secret passed by `LoadCredential` and precise
      firewall rules rather than a trusted interface.

Deliberately not built:

- **A per-port allowlist.** [DESIGN.md](DESIGN.md) decides against it: the managed range is the only
  limit, and that is stated rather than hedged.
- **IPv6 on the desktop datapath.** The tc programs count IPv6 and pass it through, and
  `connect6` now *declines* rather than rewriting to the unspecified address when no v6 target is
  configured. Room is reserved in `SleeveConfig`, in the tc counter indices, and in
  `transport::Plan`, so adding it is new code rather than a layout change.
- **A tracepoint-driven listener feed**, replacing the 250ms poll.
- **A netlink monitor socket** for network-change detection; an address and route snapshot compared
  on each loop tick is what is built.

Deleted rather than deferred:

- Certificate and token machinery. WireGuard authenticates the peer.
- The `sock_ops` cookie-to-source-port handoff, the rendezvous socket, and sockmap splicing. All
  three belonged to architectures this design replaced.
- Rung C, and both wire-level variants of Rung B. Measured, recorded in
  [FINDINGS.md](FINDINGS.md), and removed — Rung A went with them once the product had only one
  mode.
