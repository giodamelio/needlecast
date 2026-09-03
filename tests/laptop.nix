{
  pkgs,
  testers,
  needlecast,
  kernelPackages,
  variant,
}: let
  nodes = import ./lib/nodes.nix {inherit pkgs needlecast kernelPackages;};
  probe = import ./lib/probe.nix {inherit pkgs;};
in
  testers.runNixOSTest {
    name = "needlecast-laptop-${variant}";

    nodes.laptop = {...}: {
      imports = [nodes.laptop];
      environment.systemPackages = [probe];
    };

    testScript = ''
      PORT = 8080
      OUT_OF_RANGE = 9500
      TARGET4 = "10.7.0.2"
      TARGET6 = "fd00:7::2"

      laptop.wait_for_unit("multi-user.target")

      # Record the kernel under test, so a passing run is unambiguous about what it proved.
      kernel = laptop.succeed("uname -r").strip()
      print(f"kernel under test: {kernel}")
      assert kernel.startswith("${kernelPackages.kernel.version}"), kernel

      # A dummy interface stands in for the desktop's tunnel address, so `connect4` gets to rewrite
      # a loopback destination to a genuinely non-loopback one exactly as it will in production.
      laptop.succeed("ip link add nc-desktop type dummy")
      laptop.succeed(f"ip addr add {TARGET4}/32 dev nc-desktop")
      laptop.succeed(f"ip -6 addr add {TARGET6}/128 dev nc-desktop")
      laptop.succeed("ip link set nc-desktop up")

      def start_loader(extra=""):
          laptop.succeed("rm -f /run/needlecast/client.ready")
          laptop.succeed(
              "systemd-run --unit=needlecast --collect "
              f"needlecast harness bridge --port-lo 8000 --port-hi 8999 "
              f"--target-v4 {TARGET4} --target-v6 {TARGET6} {extra}"
          )
          try:
              laptop.wait_until_succeeds("test -e /run/needlecast/client.ready", timeout=30)
          except Exception:
              print(laptop.succeed("journalctl -u needlecast.service --no-pager || true"))
              raise

      def stop_loader():
          laptop.succeed("systemctl stop needlecast.service || true")
          laptop.succeed("rm -rf /sys/fs/bpf/needlecast/client /run/needlecast/client.ready || true")

      def counters():
          out = laptop.succeed("needlecast dev counters || true")
          d = {}
          for line in out.strip().splitlines():
              if "=" in line:
                  k, v = line.split("=", 1)
                  d[k] = int(v)
          return d

      def delta(before, key):
          return counters().get(key, 0) - before.get(key, 0)

      def serve(name, bind, port, token, extra=""):
          laptop.succeed(
              f"systemd-run --unit={name} --collect "
              f"nc-probe serve --bind {bind} --port {port} --token {token} {extra}"
          )

      def stop(name):
          laptop.succeed(f"systemctl stop {name}.service || true")

      def connect(host, port, extra="", netns=None):
          cmd = f"nc-probe connect --host {host} --port {port} {extra}"
          if netns:
              cmd = f"ip netns exec {netns} " + cmd
          out = laptop.succeed(cmd + " || true")
          d = {}
          for line in out.strip().splitlines():
              if "=" in line:
                  k, v = line.split("=", 1)
                  d[k] = v
          return d

      def wait_listening(addr, port, proto="tcp"):
          flag = "-t" if proto == "tcp" else "-u"
          laptop.wait_until_succeeds(
              f"ss -ln {flag} | grep -q '{addr}:{port}'", timeout=30
          )

      with subtest("the embedded object parses"):
          print(laptop.succeed("needlecast dev verify-object"))
          print(laptop.succeed("mount | grep bpf || true"))
          laptop.succeed("test -e /sys/kernel/btf/vmlinux")

      with subtest("smoke: all nine programs load and attach"):
          laptop.succeed("needlecast dev probe-syncnt > /tmp/syncnt-result; echo rc=$? >> /tmp/syncnt-result")
          print("probe-syncnt: " + laptop.succeed("cat /tmp/syncnt-result"))
          start_loader("--syncnt-probe")
          ready = laptop.succeed("cat /run/needlecast/client.ready")
          print("ready file:\n" + ready)
          attached = dict(
              l.split("=", 1) for l in ready.strip().splitlines() if "=" in l
          )["attached"].split(",")
          for want in ["connect4", "connect6", "getpeername4", "getpeername6",
                       "sendmsg4", "sendmsg6", "recvmsg4", "recvmsg6",
                       "connect4_syncnt_probe"]:
              assert want in attached, f"{want} not attached: {attached}"
          print(laptop.succeed("bpftool cgroup tree /sys/fs/cgroup || true"))
          print(laptop.succeed("bpftool link list || true"))

      with subtest("question 3+4: no local listener, connection is rewritten to the target"):
          serve("desktop", TARGET4, PORT, "desktop")
          wait_listening(TARGET4, PORT)
          before = counters()
          r = connect("127.0.0.1", PORT)
          assert r.get("data") == "desktop", r
          assert delta(before, "connect4.rewritten") == 1, counters()

      with subtest("TCP_SYNCNT: bpf_setsockopt succeeds at runtime, not just at load"):
          before = counters()
          connect("127.0.0.1", PORT)
          ok = delta(before, "connect4.setsockopt_ok")
          err = delta(before, "connect4.setsockopt_err")
          print(f"bpf_setsockopt(TCP_SYNCNT): ok +{ok}, err +{err}")
          assert ok >= 1 and err == 0, counters()
          laptop.succeed(
              f"echo 'runtime ok={ok} err={err}' >> /tmp/syncnt-result"
          )

      with subtest("getpeername4 unwinds the rewrite"):
          before = counters()
          r = connect("127.0.0.1", PORT)
          assert r.get("peer") == f"127.0.0.1:{PORT}", r
          assert delta(before, "getpeername4.restored") >= 1, counters()

      with subtest("local listener wins over the rewrite"):
          serve("local", "127.0.0.1", PORT, "local")
          wait_listening("127.0.0.1", PORT)
          before = counters()
          r = connect("127.0.0.1", PORT)
          assert r.get("data") == "local", r
          assert r.get("peer") == f"127.0.0.1:{PORT}", r
          assert delta(before, "connect4.local_listener") == 1, counters()
          assert delta(before, "connect4.rewritten") == 0, counters()

      with subtest("reversion: killing the local listener restores forwarding"):
          stop("local")
          laptop.wait_until_fails(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
          r = connect("127.0.0.1", PORT)
          assert r.get("data") == "desktop", r

      with subtest("a wildcard bind also wins"):
          serve("wild", "0.0.0.0", 8081, "wildcard")
          wait_listening("0.0.0.0", 8081)
          before = counters()
          r = connect("127.0.0.1", 8081)
          assert r.get("data") == "wildcard", r
          assert delta(before, "connect4.local_listener") == 1, counters()
          stop("wild")

      with subtest("ports outside the managed range are untouched"):
          serve("oor", TARGET4, OUT_OF_RANGE, "out-of-range")
          wait_listening(TARGET4, OUT_OF_RANGE)
          before = counters()
          r = connect("127.0.0.1", OUT_OF_RANGE)
          assert r.get("error") == "ECONNREFUSED", r
          assert delta(before, "connect4.port_out_of_range") == 1, counters()
          stop("oor")

      with subtest("non-loopback destinations are untouched"):
          before = counters()
          r = connect(TARGET4, PORT)
          assert r.get("data") == "desktop", r
          assert delta(before, "connect4.rewritten") == 0, counters()
          assert delta(before, "connect4.not_loopback") >= 1, counters()

      with subtest("the netns guard declines inside another namespace"):
          laptop.succeed("ip netns add probe-ns")
          laptop.succeed("ip netns exec probe-ns ip link set lo up")
          before = counters()
          r = connect("127.0.0.1", PORT, netns="probe-ns")
          assert r.get("error") == "ECONNREFUSED", r
          assert delta(before, "connect4.wrong_netns") == 1, counters()

      with subtest("clearing the enabled flag restores stock behaviour"):
          laptop.succeed("needlecast dev set-enabled 0")
          before = counters()
          r = connect("127.0.0.1", PORT)
          assert r.get("error") == "ECONNREFUSED", r
          assert delta(before, "connect4.disabled") == 1, counters()
          laptop.succeed("needlecast dev set-enabled 1")
          r = connect("127.0.0.1", PORT)
          assert r.get("data") == "desktop", r

      with subtest("the listener map gates the rewrite when enabled"):
          stop_loader()
          start_loader("--use-listener-map")
          before = counters()
          r = connect("127.0.0.1", PORT)
          assert r.get("error") == "ECONNREFUSED", r
          assert delta(before, "connect4.not_advertised") == 1, counters()
          laptop.succeed(f"needlecast dev advertise {PORT}")
          r = connect("127.0.0.1", PORT)
          assert r.get("data") == "desktop", r
          stop_loader()
          start_loader()

      with subtest("connect6 rewrites ::1 to the v6 target"):
          serve("desktop6", TARGET6, PORT, "desktop6", "--v6")
          wait_listening(f"\\[{TARGET6}\\]", PORT)
          before = counters()
          r = connect("::1", PORT, "--v6")
          assert r.get("data") == "desktop6", r
          assert r.get("peer") == f"::1:{PORT}", r
          assert delta(before, "connect6.rewritten") == 1, counters()
          assert delta(before, "getpeername6.restored") >= 1, counters()

      with subtest("connect6 handles IPv4-mapped destinations"):
          before = counters()
          r = connect("::ffff:127.0.0.1", PORT, "--v6")
          assert r.get("data") == "desktop", r
          assert delta(before, "connect6.rewritten") == 1, counters()
          # A dual-stack program asking for `localhost` arrives here rather than in connect4, so
          # leaving the SYN cap off this path would give exactly those programs the stock
          # two-minute hang when the server vanishes.
          assert delta(before, "connect6.setsockopt_ok") == 1, counters()
          assert delta(before, "connect6.setsockopt_err") == 0, counters()

      with subtest("question 6: UDP unconnected sockets go through sendmsg4"):
          serve("udp-desktop", TARGET4, PORT, "udp-desktop", "--udp")
          wait_listening(TARGET4, PORT, "udp")
          before = counters()
          r = connect("127.0.0.1", PORT, "--udp --unconnected")
          assert r.get("data", "").startswith("udp-desktop"), r
          assert delta(before, "sendmsg4.rewritten") == 1, counters()
          # TCP_SYNCNT is meaningless on a UDP socket, so it is not attempted rather than attempted
          # and failed — otherwise every datagram would bury the real setsockopt_err signal.
          assert delta(before, "sendmsg4.setsockopt_ok") == 0, counters()
          assert delta(before, "sendmsg4.setsockopt_err") == 0, counters()

      with subtest("recvmsg4 restores the source address on UDP replies"):
          before = counters()
          r = connect("127.0.0.1", PORT, "--udp --unconnected")
          assert r.get("peer") == f"127.0.0.1:{PORT}", r
          assert delta(before, "recvmsg4.restored") >= 1, counters()

      with subtest("question 7: connected UDP sockets go through connect4"):
          before = counters()
          r = connect("127.0.0.1", PORT, "--udp")
          assert r.get("data", "").startswith("udp-desktop"), r
          c4 = delta(before, "connect4.rewritten")
          s4 = delta(before, "sendmsg4.rewritten")
          print(f"connected UDP: connect4.rewritten +{c4}, sendmsg4.rewritten +{s4}")
          assert c4 + s4 >= 1, counters()

      with subtest("a local UDP listener wins"):
          serve("udp-local", "127.0.0.1", PORT, "udp-local", "--udp")
          wait_listening("127.0.0.1", PORT, "udp")
          r = connect("127.0.0.1", PORT, "--udp --unconnected")
          assert r.get("data", "").startswith("udp-local"), r
          stop("udp-local")
          laptop.wait_until_fails(f"ss -lnu | grep -q '127.0.0.1:{PORT}'", timeout=30)

      # TCP decides once at connect() and an established connection is never re-evaluated. An
      # unconnected UDP socket has no such moment, so it must re-decide per datagram — asserted
      # here on a single socket rather than assumed.
      with subtest("an unconnected UDP socket re-evaluates local-wins on every datagram"):
          laptop.succeed("rm -f /tmp/udp-gate /tmp/udp-repeat.out")
          laptop.succeed(
              "setsid nc-probe connect --host 127.0.0.1 "
              f"--port {PORT} --udp --unconnected --repeat 2 --gate /tmp/udp-gate "
              "--timeout 30 > /tmp/udp-repeat.out 2>&1 &"
          )
          laptop.wait_until_succeeds("grep -q '^data=' /tmp/udp-repeat.out", timeout=30)

          serve("udp-local2", "127.0.0.1", PORT, "udp-local2", "--udp")
          wait_listening("127.0.0.1", PORT, "udp")
          laptop.succeed("touch /tmp/udp-gate")

          laptop.wait_until_succeeds("grep -q '^data2=' /tmp/udp-repeat.out", timeout=30)
          out = laptop.succeed("cat /tmp/udp-repeat.out")
          print(out)
          r = {}
          for line in out.strip().splitlines():
              if "=" in line:
                  k, v = line.split("=", 1)
                  r[k] = v
          assert r.get("data", "").startswith("udp-desktop"), r
          assert r.get("data2", "").startswith("udp-local2"), r
          # The source address is restored on both, so the application cannot tell them apart.
          assert r.get("peer") == f"127.0.0.1:{PORT}", r
          assert r.get("peer2") == f"127.0.0.1:{PORT}", r
          stop("udp-local2")
          laptop.wait_until_fails(f"ss -lnu | grep -q '127.0.0.1:{PORT}'", timeout=30)

      with subtest("sendmsg6 and recvmsg6 carry the UDP path over IPv6"):
          serve("udp-desktop6", TARGET6, PORT, "udp-desktop6", "--udp --v6")
          wait_listening(f"\\[{TARGET6}\\]", PORT, "udp")
          before = counters()
          r = connect("::1", PORT, "--udp --unconnected --v6")
          assert r.get("data", "").startswith("udp-desktop6"), r
          assert delta(before, "sendmsg6.rewritten") == 1, counters()
          assert r.get("peer") == f"::1:{PORT}", r
          assert delta(before, "recvmsg6.restored") >= 1, counters()

      with subtest("a local IPv6 UDP listener wins"):
          serve("udp-local6", "::1", PORT, "udp-local6", "--udp --v6")
          wait_listening(r"\[::1\]", PORT, "udp")
          before = counters()
          r = connect("::1", PORT, "--udp --unconnected --v6")
          assert r.get("data", "").startswith("udp-local6"), r
          assert delta(before, "sendmsg6.local_listener") == 1, counters()
          assert delta(before, "sendmsg6.rewritten") == 0, counters()
          stop("udp-local6")

      with subtest("final counter snapshot"):
          print("--- counters ---")
          print(laptop.succeed("needlecast dev counters"))
          print("--- syncnt ---")
          print(laptop.succeed("cat /tmp/syncnt-result"))

      with subtest("killing the loader detaches everything"):
          stop_loader()
          after = laptop.succeed("bpftool cgroup show /sys/fs/cgroup")
          assert "connect4" not in after, after
          r = connect("127.0.0.1", PORT)
          assert r.get("error") == "ECONNREFUSED", r
    '';
  }
