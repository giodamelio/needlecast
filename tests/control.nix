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
    environment.systemPackages = with pkgs; [needlecast-poc probe bpftools iproute2 python3];
  };
in
  testers.runNixOSTest {
    name = "needlecast-control-${variant}";

    nodes.laptop = {...}: {imports = [common t.laptop];};
    nodes.desktop = {...}: {imports = [common t.desktop];};

    testScript = ''
      IFACE = "${t.iface}"
      LAPTOP = "${t.laptopAddr}"
      DESKTOP = "${t.desktopAddr}"
      PORT = 8080
      OTHER = 8081

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

      def config():
          return parse(laptop.succeed("needlecast-poc show-config || true"))

      def enabled():
          return config().get("enabled")

      def local(port, extra=""):
          return parse(laptop.succeed(
              f"nc-probe connect --host 127.0.0.1 --port {port} {extra} || true"
          ))

      def start_sleeve():
          desktop.succeed(f"sysctl -qw net.ipv4.conf.{IFACE}.route_localnet=1")
          desktop.succeed("rm -f /run/needlecast-sleeve.ready")
          desktop.succeed(
              "systemd-run --unit=sleeve --collect "
              f"needlecast-poc sleeve --iface {IFACE} --transport-v4 {DESKTOP} "
              f"--transport-peer-v4 {LAPTOP} --mode rung-b --port-lo 8000 --port-hi 8999"
          )
          desktop.wait_until_succeeds("test -e /run/needlecast-sleeve.ready", timeout=30)

      def start_bridge(extra=f"--control {DESKTOP}"):
          laptop.succeed("systemctl stop bridge.service 2>/dev/null || true")
          laptop.succeed("rm -f /run/needlecast-poc.ready")
          laptop.succeed(
              "systemd-run --unit=bridge --collect "
              f"needlecast-poc run --target-v4 {DESKTOP} {extra} "
              "--port-lo 8000 --port-hi 8999"
          )
          laptop.wait_until_succeeds("test -e /run/needlecast-poc.ready", timeout=30)

      def advertised():
          out = laptop.succeed(
              "bpftool map dump pinned /sys/fs/bpf/needlecast/DESKTOP_PORTS"
          )
          return out.count("key")

      with subtest("the bridge starts disabled and stays that way until the desktop answers"):
          start_bridge()
          assert enabled() == "0", config()
          # Nothing is rewritten while disabled, so this is stock behaviour.
          r = local(PORT, "--timeout 5")
          assert r.get("error") == "ECONNREFUSED", r
          print("no desktop: " + str(config()))

      with subtest("bringing the desktop up enables the bridge on its own"):
          desktop.succeed(
              f"systemd-run --unit=dev --collect "
              f"nc-probe serve --bind 127.0.0.1 --port {PORT} --token desktop"
          )
          desktop.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
          start_sleeve()
          laptop.wait_until_succeeds(
              "needlecast-poc show-config | grep -q 'enabled=1'", timeout=30
          )
          r = local(PORT)
          assert r.get("data") == "desktop", r

      with subtest("the listener set arrives, and gates ports the desktop does not serve"):
          before = parse(laptop.succeed("needlecast-poc counters || true"))
          r = local(OTHER, "--timeout 5")
          assert r.get("error") == "ECONNREFUSED", r
          after = parse(laptop.succeed("needlecast-poc counters || true"))
          na = int(after.get("connect4.not_advertised", 0)) - int(
              before.get("connect4.not_advertised", 0))
          print(f"connect4.not_advertised +{na}")
          assert na >= 1, (before, after)

      with subtest("a port appearing on the desktop becomes usable without restarting anything"):
          desktop.succeed(
              f"systemd-run --unit=dev2 --collect "
              f"nc-probe serve --bind 127.0.0.1 --port {OTHER} --token desktop2"
          )
          desktop.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{OTHER}'", timeout=30)
          laptop.wait_until_succeeds(
              f"nc-probe connect --host 127.0.0.1 --port {OTHER} | grep -q desktop2", timeout=30
          )
          print("new desktop port became usable")

      with subtest("a port disappearing stops being forwarded"):
          desktop.succeed("systemctl stop dev2.service")
          desktop.wait_until_fails(f"ss -lnt | grep -q '127.0.0.1:{OTHER}'", timeout=30)
          print("desktop now serves: " + desktop.succeed("needlecast-poc listeners | tr '\n' ' '"))
          import time as _t
          for _ in range(30):
              r = local(OTHER, "--timeout 5")
              if r.get("error"):
                  break
              _t.sleep(1)
          print(f"after withdrawal: {r}  advertised entries: {advertised()}")
          assert r.get("error") == "ECONNREFUSED", r

      with subtest("killing the sleeve disables the bridge and clears the listener set"):
          desktop.succeed("systemctl stop sleeve.service")
          laptop.wait_until_succeeds(
              "needlecast-poc show-config | grep -q 'enabled=0'", timeout=30
          )
          # Cleared, not left stale: a stale set is worse than none.
          assert advertised() == 0, "listener set not cleared on disconnect"
          r = local(PORT, "--timeout 5")
          assert r.get("error") == "ECONNREFUSED", r

      with subtest("the bridge reconnects on its own when the desktop returns"):
          start_sleeve()
          laptop.wait_until_succeeds(
              "needlecast-poc show-config | grep -q 'enabled=1'", timeout=60
          )
          r = local(PORT)
          assert r.get("data") == "desktop", r

      with subtest("TCP_SYNCNT is applied to rewritten sockets"):
          before = parse(laptop.succeed("needlecast-poc counters || true"))
          local(PORT)
          after = parse(laptop.succeed("needlecast-poc counters || true"))
          ok = int(after.get("connect4.setsockopt_ok", 0)) - int(
              before.get("connect4.setsockopt_ok", 0))
          err = int(after.get("connect4.setsockopt_err", 0)) - int(
              before.get("connect4.setsockopt_err", 0))
          print(f"setsockopt ok +{ok} err +{err}")
          assert ok >= 1 and err == 0, (before, after)

      # The window the cap exists for: the desktop is gone but the heartbeat has not noticed. Run
      # without a control plane so `enabled` stays set, which is the only way to hold the window
      # open long enough to measure it.
      with subtest("TCP_SYNCNT bounds how long a connection to a vanished desktop hangs"):
          desktop.succeed(f"ip link set {IFACE} down")

          def time_connect(syncnt):
              start_bridge(f"--syncnt {syncnt}")
              t0 = int(laptop.succeed("date +%s").strip())
              r = local(PORT, "--timeout 120")
              t1 = int(laptop.succeed("date +%s").strip())
              return t1 - t0, r

          low, r_low = time_connect(1)
          high, r_high = time_connect(4)
          print(f"syncnt=1 took {low}s ({r_low}); syncnt=4 took {high}s ({r_high})")
          # Both must fail rather than hang forever, and the knob must visibly move the deadline —
          # otherwise the cap is not actually being applied.
          assert low < 30, f"syncnt=1 took {low}s"
          assert high > low, f"syncnt=4 ({high}s) should exceed syncnt=1 ({low}s)"
          desktop.succeed(f"ip link set {IFACE} up")

      with subtest("final config"):
          print(laptop.succeed("needlecast-poc show-config"))
    '';
  }
