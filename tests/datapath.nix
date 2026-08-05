{
  pkgs,
  testers,
  needlecast,
  kernelPackages,
  variant,
  transport,
}: let
  probe = import ./lib/probe.nix {inherit pkgs;};
  transports = import ./lib/transport.nix {inherit pkgs;};
  t = transports.${transport};

  common = {
    boot.kernelPackages = kernelPackages;
    networking.firewall.enable = false;
    virtualisation.vlans = [1];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    virtualisation.diskSize = 4096;
    environment.systemPackages = with pkgs; [
      needlecast
      probe
      bpftools
      iproute2
      python3
      tcpdump
      wireguard-tools
    ];
  };
in
  testers.runNixOSTest {
    name = "needlecast-datapath-${transport}-${variant}";

    nodes.laptop = {...}: {imports = [common t.laptop];};
    nodes.desktop = {...}: {imports = [common t.desktop];};

    testScript = ''
      IFACE = "${t.iface}"
      LAPTOP = "${t.laptopAddr}"
      DESKTOP = "${t.desktopAddr}"
      MTU = ${toString t.mtu}
      PORT = 8080
      OUT_OF_RANGE = 9500

      start_all()
      for m in (laptop, desktop):
          m.wait_for_unit("multi-user.target")
          k = m.succeed("uname -r").strip()
          assert k.startswith("${kernelPackages.kernel.version}"), k
      print(f"kernel: {laptop.succeed('uname -r').strip()}  transport: ${transport}")

      for m in (laptop, desktop):
          m.wait_until_succeeds(f"ip -4 addr show {IFACE} | grep -q 'inet '", timeout=60)
      print("underlay: laptop=" + laptop.succeed("getent hosts laptop").split()[0]
            + " desktop=" + laptop.succeed("getent hosts desktop").split()[0])
      try:
          laptop.wait_until_succeeds(f"ping -c1 -W2 {DESKTOP}", timeout=60)
      except Exception:
          for m, n in ((laptop, "laptop"), (desktop, "desktop")):
              print(f"--- {n} ---")
              print(m.succeed("ip -4 addr show"))
              print(m.succeed("ip route show"))
              print(m.succeed("wg show || true"))
              print(m.succeed("journalctl -u wireguard-wg0.service --no-pager || true"))
          raise
      print(desktop.succeed(f"ip -d link show {IFACE}"))

      def parse(out):
          d = {}
          for line in out.strip().splitlines():
              if "=" in line:
                  k, v = line.split("=", 1)
                  d[k] = v
          return d

      def tc_counters():
          out = desktop.succeed("needlecast dev tc-counters || true")
          return {k: int(v) for k, v in parse(out).items()}

      def tc_delta(before, key):
          return tc_counters().get(key, 0) - before.get(key, 0)

      def start_datapath():
          desktop.succeed("rm -f /run/needlecast/server.ready")
          desktop.succeed(
              "systemd-run --unit=ncdatapath --collect "
              f"needlecast harness datapath --iface {IFACE} --transport-v4 {DESKTOP} "
              f"--transport-peer-v4 {LAPTOP} "
              "--port-lo 8000 --port-hi 8999"
          )
          try:
              desktop.wait_until_succeeds("test -e /run/needlecast/server.ready", timeout=30)
          except Exception:
              print(desktop.succeed("journalctl -u ncdatapath.service --no-pager || true"))
              raise

      def stop_datapath():
          desktop.succeed("systemctl stop ncdatapath.service || true")
          desktop.succeed(f"tc qdisc del dev {IFACE} clsact 2>/dev/null || true")
          desktop.succeed("rm -rf /sys/fs/bpf/needlecast/server /run/needlecast/server.ready")

      def serve(name, bind, port, token, extra=""):
          desktop.succeed(
              f"systemd-run --unit={name} --collect "
              f"nc-probe serve --bind {bind} --port {port} --token {token} {extra}"
          )

      def connect(port, extra="", host=None):
          host = host or DESKTOP
          return parse(laptop.succeed(
              f"nc-probe connect --host {host} --port {port} {extra} || true"
          ))

      def sysctl(m, key, value):
          m.succeed(f"sysctl -qw {key}={value}")

      with subtest("baseline: without the datapath, a loopback-bound server is unreachable"):
          serve("dev", "127.0.0.1", PORT, "desktop")
          desktop.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
          r = connect(PORT)
          assert r.get("error") in ("ECONNREFUSED", "TIMEOUT"), r
          print(f"baseline failure mode: {r}")

      with subtest("question 1: the tc datapath delivers into a 127.0.0.1-bound server"):
          sysctl(desktop, f"net.ipv4.conf.{IFACE}.route_localnet", 1)
          start_datapath()
          before = tc_counters()
          r = connect(PORT)
          assert r.get("data") == "desktop", r
          assert tc_delta(before, "tc_ingress.rewritten_tcp") >= 1, tc_counters()
          assert tc_delta(before, "tc_egress.rewritten_tcp") >= 1, tc_counters()

      with subtest("the server sees a genuine loopback connection"):
          serve("dev2", "127.0.0.1", 8081, "desktop2", "--hold 60")
          desktop.wait_until_succeeds("ss -lnt | grep -q '127.0.0.1:8081'", timeout=30)
          laptop.succeed(
              f"setsid nc-probe connect --host {DESKTOP} --port 8081 --hold 30 "
              "> /tmp/hold.out 2>&1 &"
          )
          laptop.wait_until_succeeds("grep -q '^data=' /tmp/hold.out", timeout=30)
          desktop.wait_until_succeeds(
              "ss -tn state established | grep -q ':8081'", timeout=30
          )
          established = desktop.succeed("ss -tn state established | grep ':8081'")
          print(established)
          assert "127.0.0.1:8081" in established, established
          # The wire is never rewritten on the source side inbound, so the kernel's peer is the
          # client's transport address. What the *application* is told is covered separately.
          assert LAPTOP in established, established

      # The server's socket is on loopback, whose MTU is 65536, but the segments have to fit the
      # transport. The client's SYN advertises against its own route, so this should fall out
      # without anything clamping it — asserted because "should fall out" is a prediction.
      with subtest("MSS is negotiated against the transport MTU, not loopback's"):
          info = desktop.succeed("ss -tni state established | grep -A1 ':8081' | head -4")
          print(info)
          mss = None
          for tok in info.split():
              if tok.startswith("mss:"):
                  mss = int(tok.split(":", 1)[1])
                  break
          print(f"negotiated mss={mss} transport mtu={MTU}")
          assert mss is not None, info
          assert mss <= MTU - 40, f"mss {mss} does not fit an MTU of {MTU}"
          assert mss > MTU - 100, f"mss {mss} is suspiciously far below the MTU {MTU}"

      with subtest("determine which sysctls are actually required"):
          results = {}
          for key, value in [
              (f"net.ipv4.conf.{IFACE}.route_localnet", 0),
              (f"net.ipv4.conf.{IFACE}.rp_filter", 1),
              ("net.ipv4.conf.all.rp_filter", 1),
          ]:
              old = desktop.succeed(f"sysctl -n {key}").strip()
              sysctl(desktop, key, value)
              r = connect(PORT)
              results[f"{key}={value}"] = "works" if r.get("data") == "desktop" else str(r)
              sysctl(desktop, key, old)
              assert connect(PORT).get("data") == "desktop", "failed to restore"
          for k, v in sorted(results.items()):
              print(f"sysctl {k}: {v}")
          assert results[f"net.ipv4.conf.{IFACE}.route_localnet=0"] != "works", results
          desktop.succeed(
              "echo '" + "; ".join(f"{k} -> {v}" for k, v in sorted(results.items()))
              + "' > /tmp/sysctl-findings"
          )

      with subtest("all.route_localnet is not required when the per-interface one is set"):
          allv = desktop.succeed("sysctl -n net.ipv4.conf.all.route_localnet").strip()
          print(f"net.ipv4.conf.all.route_localnet={allv}")
          assert allv == "0", "the per-interface setting alone should be doing the work"
          assert connect(PORT).get("data") == "desktop"

      with subtest("ports outside the managed range are untouched"):
          serve("oor", "127.0.0.1", OUT_OF_RANGE, "out-of-range")
          desktop.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{OUT_OF_RANGE}'", timeout=30)
          before = tc_counters()
          r = connect(OUT_OF_RANGE)
          assert r.get("error") in ("ECONNREFUSED", "TIMEOUT"), r
          assert tc_delta(before, "tc_ingress.port_out_of_range") >= 1, tc_counters()

      with subtest("question 5: a 200MB transfer survives GSO and the checksum fixups"):
          desktop.succeed("head -c 209715200 /dev/urandom > /tmp/blob")
          want = desktop.succeed("sha256sum /tmp/blob").split()[0]
          serve("bulk", "127.0.0.1", 8082, "unused", "--file /tmp/blob")
          desktop.wait_until_succeeds("ss -lnt | grep -q '127.0.0.1:8082'", timeout=30)
          r = parse(laptop.succeed(
              f"nc-probe connect --host {DESKTOP} --port 8082 --out /tmp/blob --timeout 300"
          ))
          print(f"received {r.get('bytes')} bytes")
          assert int(r["bytes"]) == 209715200, r
          got = laptop.succeed("sha256sum /tmp/blob").split()[0]
          assert got == want, f"{got} != {want}"

      with subtest("UDP round trips byte-identically"):
          serve("udp", "127.0.0.1", 8083, "udp-desktop", "--udp")
          desktop.wait_until_succeeds("ss -lnu | grep -q '127.0.0.1:8083'", timeout=30)
          before = tc_counters()
          r = connect(8083, "--udp --unconnected")
          assert r.get("data", "").startswith("udp-desktop"), r
          assert tc_delta(before, "tc_ingress.rewritten_udp") >= 1, tc_counters()

      with subtest("a UDP datagram larger than the MTU survives fragmentation"):
          size = MTU * 4
          before = tc_counters()
          r = connect(8083, f"--udp --unconnected --payload-size {size} --timeout 30")
          print(f"echo_len={r.get('echo_len')} echo_ok={r.get('echo_ok')}")
          assert r.get("echo_ok") == "True", r
          frags = tc_delta(before, "tc_ingress.not_first_fragment")
          print(f"non-first fragments seen inbound: {frags}")

      with subtest("an IPv4 UDP datagram with a zero checksum keeps it"):
          # If the fixup recomputed a checksum over a zero field the receiver would drop the
          # datagram, so a successful echo is the assertion.
          r = connect(8083, "--udp --unconnected --no-check --timeout 20")
          assert r.get("data", "").startswith("udp-desktop"), r

      # The design assumed a per-interface sysctl and a per-interface one is what it needs. Asserted
      # so a future change that reaches for `all` fails here rather than in review.
      with subtest("nothing outside the transport interface is touched"):
          for key in ("net.ipv4.conf.all.route_localnet",
                      "net.ipv4.conf.lo.route_localnet",
                      "net.ipv4.conf.default.route_localnet"):
              assert desktop.succeed(f"sysctl -n {key}").strip() == "0", key
          assert connect(PORT).get("data") == "desktop"

      with subtest("clearing the datapath restores stock behaviour"):
          stop_datapath()
          r = connect(PORT)
          assert r.get("error") in ("ECONNREFUSED", "TIMEOUT"), r
          start_datapath()

      # The requirement is that the dev server cannot tell a forwarded connection from a local one.
      # Measured as what the server *application* is told, since that is what the requirement is
      # about — `ss` reads the kernel socket table and is shown only for contrast.
      with subtest("the server cannot distinguish a forwarded connection from a local one"):

          def app_peer(unit, port):
              desktop.wait_until_succeeds(
                  f"journalctl -u {unit} --no-pager | grep -q accepted_peer=", timeout=15
              )
              line = desktop.succeed(
                  f"journalctl -u {unit} --no-pager | grep accepted_peer= | tail -1"
              ).strip()
              return line.split("accepted_peer=")[1].rsplit(":", 1)[0]

          def remote_connect(port):
              laptop.succeed(f"rm -f /tmp/inv{port}.out")
              laptop.succeed(
                  f"setsid nc-probe connect --host {DESKTOP} --port {port} --hold 60 "
                  f"--timeout 10 > /tmp/inv{port}.out 2>&1 &"
              )
              laptop.wait_until_succeeds(
                  f"grep -qE '^(data|error)=' /tmp/inv{port}.out", timeout=15
              )
              return parse(laptop.succeed(f"cat /tmp/inv{port}.out"))

          serve("inv8085", "127.0.0.1", 8085, "invisible", "--hold 120")
          desktop.wait_until_succeeds("ss -lnt | grep -q '127.0.0.1:8085'", timeout=30)
          r = remote_connect(8085)
          assert "data" in r, r
          kernel_view = desktop.succeed(
              "ss -tn state established | grep '127.0.0.1:8085 '"
          ).strip().split()[-1].rsplit(":", 1)[0]
          forwarded = app_peer("inv8085", 8085)
          print(f"server sees={forwarded}  ss shows={kernel_view}")

          assert forwarded == "127.0.0.1", forwarded
          # `ss` still shows the truth, which is a feature: the operator debugging the machine
          # sees the real tunnel address while the application sees loopback.
          assert kernel_view == LAPTOP, kernel_view

          # The point of the whole exercise: byte-identical to a connection made on the server
          # itself, so no comparison a server can make through the socket API separates them.
          serve("localsrv", "127.0.0.1", 8087, "invisible", "--hold 120")
          desktop.wait_until_succeeds("ss -lnt | grep -q '127.0.0.1:8087'", timeout=30)
          desktop.succeed(
              "setsid nc-probe connect --host 127.0.0.1 --port 8087 --hold 30 "
              "> /tmp/local.out 2>&1 &"
          )
          genuinely_local = app_peer("localsrv", 8087)
          print(f"a genuinely local connection reports: {genuinely_local}")
          assert forwarded == genuinely_local, (forwarded, genuinely_local)

      # Nothing outside the interface needlecast creates: no route, no attachment to lo, and no
      # sysctl anywhere else.
      with subtest("the datapath touches nothing else on the machine"):
          ready = desktop.succeed("cat /run/needlecast/server.ready")
          print(ready)
          assert "sleeve_getpeername4" in ready, ready
          assert "clsact" not in desktop.succeed("tc qdisc show dev lo")
          routes = desktop.succeed("ip route show table local")
          assert "127.0.0.0/8 dev lo" in routes, routes
          assert IFACE not in routes.split("127.0.0.0/8")[1].split(chr(10))[0], routes
          for key in ("net.ipv4.conf.all.route_localnet",
                      "net.ipv4.conf.lo.route_localnet",
                      "net.ipv4.conf.default.route_localnet"):
              assert desktop.succeed(f"sysctl -n {key}").strip() == "0", key

      with subtest("bulk and UDP survive"):
          r = parse(laptop.succeed(
              f"nc-probe connect --host {DESKTOP} --port 8082 --out /tmp/blob2 --timeout 300"
          ))
          assert int(r["bytes"]) == 209715200, r
          assert laptop.succeed("sha256sum /tmp/blob2").split()[0] == want
          r = connect(8083, "--udp --unconnected")
          assert r.get("data", "").startswith("udp-desktop"), r
          r = connect(8083, f"--udp --unconnected --payload-size {MTU * 4} --timeout 30")
          assert r.get("echo_ok") == "True", r

      with subtest("final tc counter snapshot"):
          connect(PORT)
          print(desktop.succeed("needlecast dev tc-counters"))
          print(desktop.succeed("cat /tmp/sysctl-findings"))
    '';
  }
