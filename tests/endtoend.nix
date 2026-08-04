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
    virtualisation.diskSize = 4096;
    environment.systemPackages = with pkgs; [
      needlecast-poc
      probe
      bpftools
      iproute2
      python3
      tcpdump
      wireguard-tools
    ];
  };
in
  # The first time both halves run together. Everything until now proved the laptop and the desktop
  # in isolation; this proves they agree.
  testers.runNixOSTest {
    name = "needlecast-endtoend-${variant}";

    nodes.laptop = {...}: {imports = [common t.laptop];};
    nodes.desktop = {...}: {imports = [common t.desktop];};

    testScript = ''
      IFACE = "${t.iface}"
      LAPTOP = "${t.laptopAddr}"
      DESKTOP = "${t.desktopAddr}"
      MTU = ${toString t.mtu}
      PORT = 8080
      UDP_PORT = 8053

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

      def counters(m, cmd):
          out = m.succeed(f"needlecast-poc {cmd} || true")
          return {k: int(v) for k, v in parse(out).items()}

      def start_bridge():
          laptop.succeed("rm -f /run/needlecast-poc.ready")
          laptop.succeed(
              "systemd-run --unit=bridge --collect "
              f"needlecast-poc run --target-v4 {DESKTOP} --port-lo 8000 --port-hi 8999"
          )
          try:
              laptop.wait_until_succeeds("test -e /run/needlecast-poc.ready", timeout=30)
          except Exception:
              print(laptop.succeed("journalctl -u bridge.service --no-pager || true"))
              raise

      def start_sleeve():
          desktop.succeed(f"sysctl -qw net.ipv4.conf.{IFACE}.route_localnet=1")
          desktop.succeed("rm -f /run/needlecast-sleeve.ready")
          desktop.succeed(
              "systemd-run --unit=sleeve --collect "
              f"needlecast-poc sleeve --iface {IFACE} --transport-v4 {DESKTOP} "
              f"--transport-peer-v4 {LAPTOP} --mode rung-b --port-lo 8000 --port-hi 8999"
          )
          try:
              desktop.wait_until_succeeds("test -e /run/needlecast-sleeve.ready", timeout=30)
          except Exception:
              print(desktop.succeed("journalctl -u sleeve.service --no-pager || true"))
              raise

      # Everything the laptop does is addressed to plain localhost. That is the entire point: no
      # test here ever names the desktop's address.
      def local(port, extra=""):
          return parse(laptop.succeed(
              f"nc-probe connect --host 127.0.0.1 --port {port} {extra} || true"
          ))

      with subtest("bring both halves up"):
          start_sleeve()
          start_bridge()
          print(laptop.succeed("cat /run/needlecast-poc.ready"))
          print(desktop.succeed("cat /run/needlecast-sleeve.ready"))

      with subtest("localhost:8080 on the laptop reaches the desktop's dev server"):
          desktop.succeed(
              f"systemd-run --unit=dev --collect "
              f"nc-probe serve --bind 127.0.0.1 --port {PORT} --token desktop --hold 120"
          )
          desktop.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)

          before_l = counters(laptop, "counters")
          before_d = counters(desktop, "tc-counters")
          r = local(PORT)
          assert r.get("data") == "desktop", r
          # The port the user typed is preserved end to end, never translated.
          assert r.get("peer") == f"127.0.0.1:{PORT}", r

          after_l = counters(laptop, "counters")
          after_d = counters(desktop, "tc-counters")
          assert after_l.get("connect4.rewritten", 0) > before_l.get("connect4.rewritten", 0)
          assert after_l.get("getpeername4.restored", 0) > before_l.get("getpeername4.restored", 0)
          assert after_d.get("tc_ingress.rewritten_tcp", 0) > before_d.get(
              "tc_ingress.rewritten_tcp", 0)
          assert after_d.get("tc_egress.rewritten_tcp", 0) > before_d.get(
              "tc_egress.rewritten_tcp", 0)

      with subtest("both ends believe they are talking to loopback"):
          # Held open at both ends, or the socket is gone before the kernel view can be read.
          laptop.succeed("rm -f /tmp/held.out")
          laptop.succeed(
              f"setsid nc-probe connect --host 127.0.0.1 --port {PORT} --hold 60 "
              "> /tmp/held.out 2>&1 &"
          )
          laptop.wait_until_succeeds("grep -q '^data=' /tmp/held.out", timeout=20)
          client = parse(laptop.succeed("cat /tmp/held.out"))

          desktop.wait_until_succeeds(
              "journalctl -u dev --no-pager | grep -q accepted_peer=", timeout=15
          )
          line = desktop.succeed(
              "journalctl -u dev --no-pager | grep accepted_peer= | tail -1"
          ).strip()
          server_sees = line.split("accepted_peer=")[1].rsplit(":", 1)[0]
          print(f"client was told {client.get('peer')}; server was told {server_sees}")
          assert client.get("peer") == f"127.0.0.1:{PORT}", client
          assert server_sees == "127.0.0.1", line

          # Meanwhile the kernel on each side records the truth, which is what makes this
          # debuggable rather than mysterious.
          est = desktop.succeed(f"ss -tn state established | grep '127.0.0.1:{PORT} '")
          print("desktop kernel view: " + est.strip())
          assert LAPTOP in est, est
          lest = laptop.succeed(f"ss -tn state established | grep ':{PORT}'")
          print("laptop kernel view:  " + lest.strip())
          assert DESKTOP in lest, lest

      with subtest("a laptop-local listener wins over the desktop"):
          laptop.succeed(
              f"systemd-run --unit=locallistener --collect "
              f"nc-probe serve --bind 127.0.0.1 --port {PORT} --token laptop-local"
          )
          laptop.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
          before = counters(laptop, "counters")
          r = local(PORT)
          assert r.get("data") == "laptop-local", r
          after = counters(laptop, "counters")
          assert after.get("connect4.local_listener", 0) > before.get("connect4.local_listener", 0)
          assert after.get("connect4.rewritten", 0) == before.get("connect4.rewritten", 0)

      with subtest("removing it hands the port back to the desktop"):
          laptop.succeed("systemctl stop locallistener.service")
          laptop.wait_until_fails(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
          r = local(PORT)
          assert r.get("data") == "desktop", r

      with subtest("UDP works end to end"):
          desktop.succeed(
              f"systemd-run --unit=udpdev --collect "
              f"nc-probe serve --bind 127.0.0.1 --port {UDP_PORT} --token desktop-udp --udp"
          )
          desktop.wait_until_succeeds(f"ss -lnu | grep -q '127.0.0.1:{UDP_PORT}'", timeout=30)
          before = counters(laptop, "counters")
          r = local(UDP_PORT, "--udp --unconnected")
          assert r.get("data", "").startswith("desktop-udp"), r
          assert r.get("peer") == f"127.0.0.1:{UDP_PORT}", r
          after = counters(laptop, "counters")
          assert after.get("sendmsg4.rewritten", 0) > before.get("sendmsg4.rewritten", 0)
          assert after.get("recvmsg4.restored", 0) > before.get("recvmsg4.restored", 0)

      with subtest("a large UDP datagram survives the whole chain"):
          r = local(UDP_PORT, f"--udp --unconnected --payload-size {MTU * 4} --timeout 30")
          assert r.get("echo_ok") == "True", r

      with subtest("a bulk transfer survives the whole chain"):
          desktop.succeed("head -c 209715200 /dev/urandom > /tmp/blob")
          want = desktop.succeed("sha256sum /tmp/blob").split()[0]
          desktop.succeed(
              "systemd-run --unit=bulk --collect "
              "nc-probe serve --bind 127.0.0.1 --port 8082 --token unused --file /tmp/blob"
          )
          desktop.wait_until_succeeds("ss -lnt | grep -q '127.0.0.1:8082'", timeout=30)
          r = parse(laptop.succeed(
              "nc-probe connect --host 127.0.0.1 --port 8082 --out /tmp/blob --timeout 300"
          ))
          assert int(r["bytes"]) == 209715200, r
          assert laptop.succeed("sha256sum /tmp/blob").split()[0] == want

      with subtest("a port the desktop does not serve fails, and does not hang"):
          r = local(8090, "--timeout 15")
          print(f"unserved port: {r}")
          assert r.get("error") == "ECONNREFUSED", r

      with subtest("stopping the laptop bridge reverts everything"):
          laptop.succeed("systemctl stop bridge.service")
          r = local(PORT, "--timeout 10")
          assert r.get("error") == "ECONNREFUSED", r

      with subtest("final counters"):
          start_bridge()
          local(PORT)
          print("--- laptop ---")
          print(laptop.succeed("needlecast-poc counters"))
          print("--- desktop ---")
          print(desktop.succeed("needlecast-poc tc-counters"))
    '';
  }
