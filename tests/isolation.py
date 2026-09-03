PORT = 8080
UNBOUND = 8090
TARGET4 = "10.7.0.2"
TARGET6 = "fd00:7::2"

laptop.wait_for_unit("multi-user.target")
kernel = laptop.succeed("uname -r").strip()
print(f"kernel under test: {kernel}")
assert kernel.startswith(KERNEL_VERSION), kernel

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

def parse(out):
    d = {}
    for line in out.strip().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v
    return d

# Three ways to end up in a foreign network namespace while staying inside the cgroup the
# programs are attached to. All three must be left alone.
def in_podman(port, extra=""):
    return parse(laptop.succeed(
        f"podman exec isolated nc-probe connect --host 127.0.0.1 --port {port} {extra} || true"
    ))

def in_netns(port, extra=""):
    return parse(laptop.succeed(
        "systemd-run --collect --wait --pipe "
        "-p NetworkNamespacePath=/run/netns/appns "
        f"nc-probe connect --host 127.0.0.1 --port {port} {extra} 2>/dev/null || true"
    ))

def in_private_network(port, extra=""):
    return parse(laptop.succeed(
        "systemd-run --collect --wait --pipe -p PrivateNetwork=yes "
        f"nc-probe connect --host 127.0.0.1 --port {port} {extra} 2>/dev/null || true"
    ))

with subtest("set up the host side"):
    start_loader()
    laptop.succeed(
        f"systemd-run --unit=desktop --collect "
        f"nc-probe serve --bind {TARGET4} --port {PORT} --token desktop"
    )
    laptop.wait_until_succeeds(f"ss -lnt | grep -q '{TARGET4}:{PORT}'", timeout=30)
    r = parse(laptop.succeed(f"nc-probe connect --host 127.0.0.1 --port {PORT} || true"))
    assert r.get("data") == "desktop", r

with subtest("set up a podman container with its own netns"):
    laptop.succeed(f"podman load -i {IMAGE}")
    laptop.succeed(
        "podman run -d --name isolated --network=none nc-probe:test "
        f"nc-probe serve --bind 127.0.0.1 --port {PORT} --token container"
    )
    laptop.wait_until_succeeds(
        "podman exec isolated sh -c 'ss -lnt 2>/dev/null | grep -q :%d' "
        "|| podman logs isolated" % PORT,
        timeout=30,
    )

with subtest("set up a manually created netns bound to a systemd service"):
    laptop.succeed("ip netns add appns")
    laptop.succeed("ip netns exec appns ip link set lo up")
    laptop.succeed(
        "systemd-run --unit=nsapp --collect "
        "-p NetworkNamespacePath=/run/netns/appns "
        f"nc-probe serve --bind 127.0.0.1 --port {PORT} --token netns"
    )
    laptop.wait_until_succeeds(
        f"ip netns exec appns ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30
    )

with subtest("container-local traffic reaches the container's own listener"):
    before = counters()
    r = in_podman(PORT)
    assert r.get("data") == "container", r
    assert delta(before, "connect4.rewritten") == 0, counters()

with subtest("netns-local traffic reaches the namespace's own listener"):
    before = counters()
    r = in_netns(PORT)
    assert r.get("data") == "netns", r
    assert delta(before, "connect4.rewritten") == 0, counters()

# The case that actually breaks without the guard: nothing is listening in the namespace, so
# a program that does not check the netns would rewrite and send the connection somewhere the
# namespace cannot reach.
with subtest("an unbound port in a container fails cleanly, not by being redirected"):
    before = counters()
    r = in_podman(UNBOUND)
    assert r.get("error") == "ECONNREFUSED", r
    assert delta(before, "connect4.wrong_netns") >= 1, counters()
    assert delta(before, "connect4.rewritten") == 0, counters()

with subtest("an unbound port in a manual netns fails cleanly"):
    before = counters()
    r = in_netns(UNBOUND)
    assert r.get("error") == "ECONNREFUSED", r
    assert delta(before, "connect4.wrong_netns") >= 1, counters()

with subtest("an unbound port under PrivateNetwork fails cleanly"):
    before = counters()
    r = in_private_network(UNBOUND)
    assert r.get("error") == "ECONNREFUSED", r
    assert delta(before, "connect4.wrong_netns") >= 1, counters()

with subtest("the host is still forwarded while all three are isolated"):
    r = parse(laptop.succeed(f"nc-probe connect --host 127.0.0.1 --port {PORT} || true"))
    assert r.get("data") == "desktop", r

with subtest("UDP is isolated too"):
    laptop.succeed(
        "podman exec -d isolated nc-probe serve --bind 127.0.0.1 "
        f"--port {PORT} --token container-udp --udp"
    )
    before = counters()
    r = in_podman(PORT, "--udp --unconnected")
    assert r.get("data", "").startswith("container-udp"), r
    assert delta(before, "sendmsg4.rewritten") == 0, counters()

# Negative control. Without this the test would still pass if the guard were deleted, because
# every assertion above would be satisfied by a program that simply never rewrites anything.
with subtest("negative control: without the guard, container traffic is captured"):
    stop_loader()
    start_loader("--no-netns-guard")
    before = counters()
    r = in_podman(UNBOUND)
    assert delta(before, "connect4.rewritten") >= 1, counters()
    assert r.get("error") != "ECONNREFUSED", (
        f"expected the unguarded rewrite to break container traffic, got {r}"
    )
    print(f"unguarded container result: {r}")

with subtest("negative control: a container's own listener still wins without the guard"):
    # bpf_sk_lookup_tcp resolves in the caller's namespace, so container-local traffic that
    # does have a listener survives even unguarded. The guard exists for the unbound case.
    before = counters()
    r = in_podman(PORT)
    assert r.get("data") == "container", r
    assert delta(before, "connect4.local_listener") >= 1, counters()

with subtest("restoring the guard restores isolation"):
    stop_loader()
    start_loader()
    r = in_podman(UNBOUND)
    assert r.get("error") == "ECONNREFUSED", r
