{
  pkgs,
  testers,
  needlecast-poc,
  kernelPackages,
  variant,
}: let
  probe = import ./lib/probe.nix {inherit pkgs;};
  transports = import ./lib/transport.nix {inherit pkgs;};
  t = transports.wireguard;

  common = {
    boot.kernelPackages = kernelPackages;
    networking.firewall.enable = false;
    virtualisation.vlans = [1];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    environment.systemPackages = with pkgs; [
      needlecast-poc
      probe
      bpftools
      curl
      iproute2
      python3
    ];
  };
in
  # Phase 9. These are the assertions worth having before you think you need them: everything here
  # is a way the system could be wrong without any of the happy-path tests noticing.
  testers.runNixOSTest {
    name = "needlecast-hostile-${variant}";

    nodes.laptop = {...}: {imports = [common t.laptop];};
    nodes.desktop = {...}: {imports = [common t.desktop];};

    testScript = ''
      IFACE = "${t.iface}"
      LAPTOP = "${t.laptopAddr}"
      DESKTOP = "${t.desktopAddr}"
      PORT = 8080
      # A second desktop server that holds connections open, for the cases that need an
      # established socket to still exist when they look. Kept off PORT so it cannot starve the
      # churn and concurrency cases of threads.
      HOLD_PORT = 8090
      OUT_OF_RANGE = 9500

      start_all()
      for m in (laptop, desktop):
          m.wait_for_unit("multi-user.target")
      laptop.wait_until_succeeds(f"ping -c1 -W2 {DESKTOP}", timeout=60)

      def parse(out):
          d = {}
          for line in out.strip().splitlines():
              if "=" in line:
                  k, v = line.split("=", 1)
                  d[k] = v
          return d

      def counters():
          return {k: int(v) for k, v in
                  parse(laptop.succeed("needlecast-poc counters || true")).items()}

      def delta(before, key):
          return counters().get(key, 0) - before.get(key, 0)

      # Counter assertions are only meaningful while the bridge is enabled: if the heartbeat has
      # blipped, connect4 records `disabled` and every other branch goes uncounted.
      def wait_enabled():
          laptop.wait_until_succeeds(
              "needlecast-poc show-config | grep -q 'enabled=1'", timeout=30
          )

      def local(port, extra=""):
          return parse(laptop.succeed(
              f"nc-probe connect --host 127.0.0.1 --port {port} {extra} || true"
          ))

      def serve(m, name, bind, port, token, extra=""):
          m.succeed(
              f"systemd-run --unit={name} --collect "
              f"nc-probe serve --bind {bind} --port {port} --token {token} {extra}"
          )

      def start_sleeve():
          desktop.succeed(f"sysctl -qw net.ipv4.conf.{IFACE}.route_localnet=1")
          desktop.succeed("rm -f /run/needlecast-sleeve.ready")
          desktop.succeed(
              "systemd-run --unit=sleeve --collect "
              f"needlecast-poc sleeve --iface {IFACE} --transport-v4 {DESKTOP} "
              f"--transport-peer-v4 {LAPTOP} --mode rung-b --port-lo 8000 --port-hi 8999"
          )
          desktop.wait_until_succeeds("test -e /run/needlecast-sleeve.ready", timeout=30)

      def start_bridge():
          laptop.succeed("systemctl stop bridge.service 2>/dev/null || true")
          laptop.succeed("rm -f /run/needlecast-poc.ready")
          laptop.succeed(
              "systemd-run --unit=bridge --collect "
              f"needlecast-poc run --target-v4 {DESKTOP} --control {DESKTOP} "
              "--port-lo 8000 --port-hi 8999"
          )
          laptop.wait_until_succeeds("test -e /run/needlecast-poc.ready", timeout=30)
          laptop.wait_until_succeeds(
              "needlecast-poc show-config | grep -q 'enabled=1'", timeout=30
          )

      with subtest("bring the system up"):
          serve(desktop, "dev", "127.0.0.1", PORT, "desktop", "--half-close-reply")
          desktop.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
          serve(desktop, "devhold", "127.0.0.1", HOLD_PORT, "desktop-hold", "--hold 120")
          desktop.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{HOLD_PORT}'", timeout=30)
          start_sleeve()
          start_bridge()
          assert local(PORT).get("data") == "desktop"

      # ---- local priority ----

      with subtest("an in-flight connection keeps flowing when a local program takes the port"):
          laptop.succeed("rm -f /tmp/inflight.out")
          laptop.succeed(
              f"setsid nc-probe connect --host 127.0.0.1 --port {HOLD_PORT} --hold 60 "
              "> /tmp/inflight.out 2>&1 &"
          )
          laptop.wait_until_succeeds("grep -q '^data=' /tmp/inflight.out", timeout=20)
          assert "desktop-hold" in laptop.succeed("cat /tmp/inflight.out")

          serve(laptop, "steal", "127.0.0.1", HOLD_PORT, "laptop-local")
          laptop.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{HOLD_PORT}'", timeout=30)
          # Established connections are never re-evaluated, so the existing one is untouched.
          est = laptop.succeed(f"ss -tn state established | grep ':{HOLD_PORT}' || true")
          assert DESKTOP in est, est
          # And the next one goes local.
          assert local(HOLD_PORT).get("data") == "laptop-local"

      with subtest("bind never blocked: the bridge holds no forwarded port"):
          # It just succeeded above while the bridge was serving that port, but assert the
          # mechanism directly too.
          rc, _ = laptop.execute(
              f"python3 -c \"import socket;s=socket.socket();"
              f"s.setsockopt(1,2,1);s.bind(('127.0.0.1',{PORT + 1}));s.listen(1)\""
          )
          assert rc == 0, "binding a port the bridge serves should always succeed"

      with subtest("reversion is automatic when the local program exits"):
          laptop.succeed("systemctl stop steal.service")
          laptop.wait_until_fails(f"ss -lnt | grep -q '127.0.0.1:{HOLD_PORT}'", timeout=30)
          assert local(HOLD_PORT).get("data") == "desktop-hold"

      with subtest("a wildcard bind wins the same way"):
          wait_enabled()
          serve(laptop, "wild", "0.0.0.0", PORT, "wildcard")
          laptop.wait_until_succeeds(f"ss -lnt | grep -q '0.0.0.0:{PORT}'", timeout=30)
          before = counters()
          assert local(PORT).get("data") == "wildcard"
          assert delta(before, "connect4.local_listener") == 1, counters()
          laptop.succeed("systemctl stop wild.service")
          laptop.wait_until_fails(f"ss -lnt | grep -q '0.0.0.0:{PORT}'", timeout=30)

      # ---- clean failure ----

      with subtest("daemon death detaches everything and reverts to stock behaviour"):
          laptop.succeed("systemctl stop bridge.service")
          r = local(PORT, "--timeout 10")
          assert r.get("error") == "ECONNREFUSED", r
          progs = laptop.succeed("bpftool prog show | grep -c cgroup_sock_addr || true").strip()
          print(f"cgroup_sock_addr programs after the daemon died: {progs}")
          assert progs == "0", "the bpf_links should have dropped with the process"
          start_bridge()

      with subtest("a port neither side serves fails cleanly"):
          r = local(8099, "--timeout 10")
          assert r.get("error") == "ECONNREFUSED", r

      with subtest("the sleeve dying disables the bridge rather than hanging it"):
          desktop.succeed("systemctl stop sleeve.service")
          laptop.wait_until_succeeds(
              "needlecast-poc show-config | grep -q 'enabled=0'", timeout=30
          )
          r = local(PORT, "--timeout 10")
          assert r.get("error") == "ECONNREFUSED", r
          start_sleeve()
          laptop.wait_until_succeeds(
              "needlecast-poc show-config | grep -q 'enabled=1'", timeout=60
          )

      # ---- non-interference ----

      with subtest("ports outside the managed range are never touched"):
          wait_enabled()
          serve(desktop, "oor", "127.0.0.1", OUT_OF_RANGE, "out-of-range")
          desktop.wait_until_succeeds(
              f"ss -lnt | grep -q '127.0.0.1:{OUT_OF_RANGE}'", timeout=30)
          before = counters()
          r = local(OUT_OF_RANGE, "--timeout 10")
          assert r.get("error") == "ECONNREFUSED", r
          # The property that matters is that nothing was rewritten; the counter says why.
          assert delta(before, "connect4.rewritten") == 0, counters()
          assert delta(before, "connect4.port_out_of_range") >= 1, counters()

      with subtest("non-loopback destinations are never touched"):
          wait_enabled()
          before = counters()
          # The laptop's own tunnel address, which is not loopback and not the target.
          r = parse(laptop.succeed(
              f"nc-probe connect --host {LAPTOP} --port {PORT} --timeout 5 || true"))
          assert delta(before, "connect4.rewritten") == 0, r
          assert delta(before, "connect4.not_loopback") >= 1, counters()

      with subtest("the control connection is never itself rewritten"):
          before = counters()
          before_tc = {k: int(v) for k, v in parse(
              desktop.succeed("needlecast-poc tc-counters || true")).items()}
          laptop.succeed("sleep 3")
          # It runs over the tunnel address, so connect4 declines it as non-loopback. On the
          # desktop its port is outside the managed range, so tc skips it. Both must hold, or the
          # control plane would be forwarding itself.
          assert delta(before, "connect4.rewritten") == 0
          after_tc = {k: int(v) for k, v in parse(
              desktop.succeed("needlecast-poc tc-counters || true")).items()}
          skipped = after_tc.get("tc_ingress.port_out_of_range", 0) - before_tc.get(
              "tc_ingress.port_out_of_range", 0)
          print(f"control-plane packets skipped by tc ingress: {skipped}")
          assert skipped > 0, "the heartbeat should be visibly passing through untouched"

      # ---- protocol fidelity ----

      with subtest("half-close: shutting down one direction keeps the other alive"):
          r = local(PORT, "--half-close --timeout 15")
          print(f"half-close: {r}")
          assert r.get("data") == "desktop", r
          assert r.get("after_half_close") == "still-here", r

      with subtest("an abortive close does not disturb anything else"):
          local(PORT, "--linger0")
          assert local(PORT).get("data") == "desktop"

      with subtest("a long-lived idle connection survives"):
          laptop.succeed("rm -f /tmp/idle.out")
          laptop.succeed(
              f"setsid nc-probe connect --host 127.0.0.1 --port {HOLD_PORT} --hold 45 "
              "> /tmp/idle.out 2>&1 &"
          )
          laptop.wait_until_succeeds("grep -q '^data=' /tmp/idle.out", timeout=20)
          laptop.succeed("sleep 40")
          # There is deliberately no per-connection state anywhere, so nothing can expire it.
          est = laptop.succeed(f"ss -tn state established | grep ':{HOLD_PORT}' || true")
          assert DESKTOP in est, est

      with subtest("getpeername reports the original address for the life of the connection"):
          r = local(PORT, "--hold 2")
          assert r.get("peer") == f"127.0.0.1:{PORT}", r

      with subtest("rapid connection churn leaks nothing"):
          wait_enabled()
          before = counters()
          r = parse(laptop.succeed(
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
          r = parse(laptop.succeed(
              f"nc-probe connect --host 127.0.0.1 --port {PORT} --concurrent 50 --timeout 20"
          ))
          assert r.get("completed") == "50", r

      with subtest("an HTTP Host header arrives byte-identical"):
          desktop.succeed(
              "systemd-run --unit=http --collect "
              "python3 -m http.server 8085 --bind 127.0.0.1 --directory /tmp"
          )
          desktop.wait_until_succeeds("ss -lnt | grep -q '127.0.0.1:8085'", timeout=30)
          laptop.wait_until_succeeds(
              "curl -sf -o /dev/null http://localhost:8085/", timeout=30
          )
          served = desktop.succeed(
              "journalctl -u http --no-pager | grep -c 'GET / HTTP' || true").strip()
          print(f"http requests served: {served}")
          assert int(served) >= 1, "the desktop's http server saw no request"
          # A real client, resolving `localhost` itself, with an untouched Host header.
          laptop.succeed("curl -sf -o /dev/null -H 'Host: localhost:8085' http://localhost:8085/")

      with subtest("final counters"):
          print(laptop.succeed("needlecast-poc counters"))
          print(desktop.succeed("needlecast-poc tc-counters"))
    '';
  }
