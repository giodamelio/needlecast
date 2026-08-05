{
  pkgs,
  testers,
  needlecast,
  kernelPackages,
  variant,
}: let
  s = import ./lib/scenarios.nix {inherit pkgs;};
  common = s.node {inherit kernelPackages needlecast;};
in
  # The regression suite. Everything here is a way the system could be wrong without any of the
  # happy-path tests noticing.
  testers.runNixOSTest {
    name = "needlecast-hostile-${variant}";

    nodes.server = {...}: common;
    nodes.client = {...}: common;

    testScript = ''
      ${s.preamble}
      PORT = 8080
      # A second server that holds connections open, for the cases that need an established socket
      # to still exist when they look. Kept off PORT so it cannot starve the churn and concurrency
      # cases of threads.
      HOLD_PORT = 8090
      OUT_OF_RANGE = 9500

      start_all()
      for m in (server, client):
          m.wait_for_unit("multi-user.target")

      ${s.assertKernel kernelPackages ["server" "client"]}

      def delta(before, key):
          return counters(client, "counters").get(key, 0) - before.get(key, 0)

      with subtest("bring the system up"):
          serve(server, "dev", PORT, "server-side", "--half-close-reply")
          server.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
          serve(server, "devhold", HOLD_PORT, "server-hold", "--hold 120")
          server.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{HOLD_PORT}'", timeout=30)
          start_server(server, peer="client")
          start_client(client, peer="server")
          wait_enabled(client)
          assert local(client, PORT).get("data") == "server-side"

      # ---- local priority ----

      with subtest("an in-flight connection keeps flowing when a local program takes the port"):
          client.succeed("rm -f /tmp/inflight.out")
          client.succeed(
              f"setsid nc-probe connect --host 127.0.0.1 --port {HOLD_PORT} --hold 60 "
              "> /tmp/inflight.out 2>&1 &"
          )
          client.wait_until_succeeds("grep -q '^data=' /tmp/inflight.out", timeout=20)
          assert "server-hold" in client.succeed("cat /tmp/inflight.out")

          serve(client, "steal", HOLD_PORT, "client-local")
          client.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{HOLD_PORT}'", timeout=30)
          # Established connections are never re-evaluated, so the existing one is untouched.
          est = client.succeed(f"ss -tn state established | grep ':{HOLD_PORT}' || true")
          assert SERVER_ADDR in est, est
          # And the next one goes local.
          assert local(client, HOLD_PORT).get("data") == "client-local"

      with subtest("bind never blocked: the bridge holds no forwarded port"):
          # It just succeeded above while the bridge was serving that port, but assert the
          # mechanism directly too.
          rc, _ = client.execute(
              f"python3 -c \"import socket;s=socket.socket();"
              f"s.setsockopt(1,2,1);s.bind(('127.0.0.1',{PORT + 1}));s.listen(1)\""
          )
          assert rc == 0, "binding a port the bridge serves should always succeed"

      with subtest("reversion is automatic when the local program exits"):
          client.succeed("systemctl stop steal.service")
          client.wait_until_fails(f"ss -lnt | grep -q '127.0.0.1:{HOLD_PORT}'", timeout=30)
          assert local(client, HOLD_PORT).get("data") == "server-hold"

      with subtest("a wildcard bind wins the same way"):
          wait_enabled(client)
          serve(client, "wild", PORT, "wildcard", bind="0.0.0.0")
          client.wait_until_succeeds(f"ss -lnt | grep -q '0.0.0.0:{PORT}'", timeout=30)
          before = counters(client, "counters")
          assert local(client, PORT).get("data") == "wildcard"
          assert delta(before, "connect4.local_listener") == 1, counters(client, "counters")
          client.succeed("systemctl stop wild.service")
          client.wait_until_fails(f"ss -lnt | grep -q '0.0.0.0:{PORT}'", timeout=30)

      # ---- clean failure ----

      with subtest("daemon death detaches everything and reverts to stock behaviour"):
          client.succeed("systemctl stop ncclient.service")
          r = local(client, PORT, "--timeout 10")
          assert r.get("error") == "ECONNREFUSED", r
          progs = client.succeed("bpftool prog show | grep -c cgroup_sock_addr || true").strip()
          print(f"cgroup_sock_addr programs after the daemon died: {progs}")
          assert progs == "0", "the bpf_links should have dropped with the process"
          start_client(client, peer="server")

      with subtest("a port neither side serves fails cleanly"):
          r = local(client, 8099, "--timeout 10")
          assert r.get("error") == "ECONNREFUSED", r

      with subtest("the server dying disables the client rather than hanging it"):
          server.succeed("systemctl stop ncserver.service")
          client.wait_until_succeeds(
              "needlecast dev show-config | grep -q 'enabled=0'", timeout=30
          )
          r = local(client, PORT, "--timeout 10")
          assert r.get("error") == "ECONNREFUSED", r
          start_server(server, peer="client")
          client.wait_until_succeeds(
              "needlecast dev show-config | grep -q 'enabled=1'", timeout=60
          )

      # ---- non-interference ----

      with subtest("ports outside the managed range are never touched"):
          wait_enabled(client)
          serve(server, "oor", OUT_OF_RANGE, "out-of-range")
          server.wait_until_succeeds(
              f"ss -lnt | grep -q '127.0.0.1:{OUT_OF_RANGE}'", timeout=30)
          before = counters(client, "counters")
          r = local(client, OUT_OF_RANGE, "--timeout 10")
          assert r.get("error") == "ECONNREFUSED", r
          # The property that matters is that nothing was rewritten; the counter says why.
          assert delta(before, "connect4.rewritten") == 0, counters(client, "counters")
          assert delta(before, "connect4.port_out_of_range") >= 1, counters(client, "counters")

      with subtest("non-loopback destinations are never touched"):
          wait_enabled(client)
          before = counters(client, "counters")
          # The client's own tunnel address, which is not loopback and not the target.
          r = parse(client.succeed(
              f"nc-probe connect --host {CLIENT_ADDR} --port {PORT} --timeout 5 || true"))
          assert delta(before, "connect4.rewritten") == 0, r
          assert delta(before, "connect4.not_loopback") >= 1, counters(client, "counters")

      with subtest("the control connection is never itself rewritten"):
          # Hold a forwarded connection open first: the heartbeat only runs once a second while
          # something is riding the tunnel, and otherwise this would have to wait half a minute
          # for a single packet to observe.
          client.succeed("rm -f /tmp/beat.out")
          client.succeed(
              f"setsid nc-probe connect --host 127.0.0.1 --port {HOLD_PORT} --hold 30 "
              "> /tmp/beat.out 2>&1 &"
          )
          client.wait_until_succeeds("grep -q '^data=' /tmp/beat.out", timeout=20)

          before = counters(client, "counters")
          before_tc = {k: int(v) for k, v in parse(
              server.succeed("needlecast dev tc-counters || true")).items()}
          client.succeed("sleep 6")
          # It runs over the tunnel address, so connect4 declines it as non-loopback. On the
          # server its port is outside the managed range, so tc skips it. Both must hold, or the
          # control plane would be forwarding itself.
          assert delta(before, "connect4.rewritten") == 0
          after_tc = {k: int(v) for k, v in parse(
              server.succeed("needlecast dev tc-counters || true")).items()}
          skipped = after_tc.get("tc_ingress.port_out_of_range", 0) - before_tc.get(
              "tc_ingress.port_out_of_range", 0)
          print(f"control-plane packets skipped by tc ingress: {skipped}")
          assert skipped > 0, "the heartbeat should be visibly passing through untouched"

      # ---- protocol fidelity ----

      with subtest("half-close: shutting down one direction keeps the other alive"):
          r = local(client, PORT, "--half-close --timeout 15")
          print(f"half-close: {r}")
          assert r.get("data") == "server-side", r
          assert r.get("after_half_close") == "still-here", r

      with subtest("an abortive close does not disturb anything else"):
          local(client, PORT, "--linger0")
          assert local(client, PORT).get("data") == "server-side"

      with subtest("a long-lived idle connection survives"):
          client.succeed("rm -f /tmp/idle.out")
          client.succeed(
              f"setsid nc-probe connect --host 127.0.0.1 --port {HOLD_PORT} --hold 45 "
              "> /tmp/idle.out 2>&1 &"
          )
          client.wait_until_succeeds("grep -q '^data=' /tmp/idle.out", timeout=20)
          client.succeed("sleep 40")
          # There is deliberately no per-connection state anywhere, so nothing can expire it.
          est = client.succeed(f"ss -tn state established | grep ':{HOLD_PORT}' || true")
          assert SERVER_ADDR in est, est

      with subtest("getpeername reports the original address for the life of the connection"):
          r = local(client, PORT, "--hold 2")
          assert r.get("peer") == f"127.0.0.1:{PORT}", r

      with subtest("rapid connection churn leaks nothing"):
          wait_enabled(client)
          before = counters(client, "counters")
          r = parse(client.succeed(
              f"nc-probe connect --host 127.0.0.1 --port {PORT} --repeat-connects 200 "
              "--timeout 10"
          ))
          assert r.get("completed") == "200", r
          rewritten = delta(before, "connect4.rewritten")
          print(f"churn: 200 connections, connect4.rewritten +{rewritten}")
          assert rewritten == 200, rewritten
          # Every rewritten socket got the SYN cap, not just the first.
          assert delta(before, "connect4.setsockopt_ok") == 200

      with subtest("many simultaneous connections all complete"):
          r = parse(client.succeed(
              f"nc-probe connect --host 127.0.0.1 --port {PORT} --concurrent 50 --timeout 20"
          ))
          assert r.get("completed") == "50", r

      with subtest("an HTTP Host header arrives byte-identical"):
          server.succeed(
              "systemd-run --unit=http --collect "
              "python3 -m http.server 8085 --bind 127.0.0.1 --directory /tmp"
          )
          server.wait_until_succeeds("ss -lnt | grep -q '127.0.0.1:8085'", timeout=30)
          client.wait_until_succeeds(
              "curl -sf -o /dev/null http://localhost:8085/", timeout=30
          )
          served = server.succeed(
              "journalctl -u http --no-pager | grep -c 'GET / HTTP' || true").strip()
          print(f"http requests served: {served}")
          assert int(served) >= 1, "the server's http server saw no request"
          # A real client, resolving `localhost` itself, with an untouched Host header.
          client.succeed("curl -sf -o /dev/null -H 'Host: localhost:8085' http://localhost:8085/")

      with subtest("final counters"):
          print(client.succeed("needlecast dev counters"))
          print(server.succeed("needlecast dev tc-counters"))
    '';
  }
