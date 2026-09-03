PORT = 8080
HOLD_PORT = 8090

start_all()
for m in (server, client):
    m.wait_for_unit("multi-user.target")

assert_kernel(server, client)

def state(m, role="client"):
    return parse(m.succeed(f"needlecast status --role {role}")).get("state")

with subtest("bring both halves up"):
    serve(server, "dev", PORT, "server-side")
    serve(server, "devhold", HOLD_PORT, "server-hold", "--hold 300")
    for p in (PORT, HOLD_PORT):
        server.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{p}'", timeout=30)
    start_server(server, peer="client")
    start_client(client, peer="server")
    wait_enabled(client)
    assert local(client, PORT).get("data") == "server-side"

with subtest("the server dies mid-flow and the client recovers with no restart"):
    client.succeed("rm -f /tmp/flow.out")
    client.succeed(
        f"setsid nc-probe connect --host 127.0.0.1 --port {HOLD_PORT} --hold 120 "
        "> /tmp/flow.out 2>&1 &"
    )
    client.wait_until_succeeds("grep -q '^data=' /tmp/flow.out", timeout=20)

    server.succeed("systemctl stop ncserver.service")
    # Disabling rather than continuing to rewrite is what the control plane exists for.
    client.wait_until_succeeds(
        "needlecast dev show-config | grep -q 'enabled=0'", timeout=60
    )
    r = local(client, PORT, "--timeout 10")
    assert r.get("error") == "ECONNREFUSED", r

    start_server(server, peer="client")
    wait_enabled(client)
    assert local(client, PORT).get("data") == "server-side"

with subtest("a crashed client leaves the interface behind, and a restart adopts it"):
    client.succeed("systemctl kill -s SIGKILL ncclient.service || true")
    client.wait_until_fails("systemctl is-active ncclient.service", timeout=30)
    client.succeed(f"ip link show {IFACE}")
    assert state(client) == "not-running", state(client)
    # Stock in the meantime: the bpf_links dropped with the process.
    r = local(client, PORT, "--timeout 10")
    assert r.get("error") == "ECONNREFUSED", r

    client.succeed("systemctl reset-failed ncclient.service || true")
    start_client(client, peer="server")
    wait_enabled(client)
    assert local(client, PORT).get("data") == "server-side"

with subtest("a crashed server leaves its interface behind, and a restart adopts it"):
    server.succeed("systemctl kill -s SIGKILL ncserver.service || true")
    server.wait_until_fails("systemctl is-active ncserver.service", timeout=30)
    server.succeed(f"ip link show {IFACE}")
    server.succeed("systemctl reset-failed ncserver.service || true")
    start_server(server, peer="client")
    wait_enabled(client)
    assert local(client, PORT).get("data") == "server-side"

# WireGuard holds a resolved endpoint forever, so a moved peer is unreachable until
# needlecast re-resolves. The only test that exercises it.
with subtest("the client re-resolves a peer whose address changed"):
    real = server.succeed("ip -4 -o addr show eth1 | awk '{print $4}'").split("/")[0].strip()
    print(f"the server is really at {real}")

    # `/etc/hosts` is a store symlink, so the swap is a bind mount over it.
    client.succeed(
        "cp /etc/hosts /tmp/hosts.bad && "
        "sed -i '/[[:space:]]server$/d' /tmp/hosts.bad && "
        "echo '192.0.2.9 server' >> /tmp/hosts.bad && "
        "mount --bind /tmp/hosts.bad /etc/hosts"
    )
    # The name cache would otherwise answer from before the swap.
    client.succeed("systemctl restart nscd.service || true")
    # `ahostsv4`: the framework also publishes an AAAA, and needlecast prefers the A.
    client.wait_until_succeeds(
        "getent ahostsv4 server | grep -q 192.0.2.9", timeout=60
    )
    server.succeed("systemctl stop ncserver.service")
    client.wait_until_succeeds(
        "needlecast dev show-config | grep -q 'enabled=0'", timeout=60
    )
    # The endpoint moving is the thing being tested, and it is checked while the server is
    # down: once it is back, its own handshake makes WireGuard roam the peer, which would
    # restore the endpoint no matter whether needlecast ever re-resolved.
    client.wait_until_succeeds(
        f"wg show {IFACE} endpoints | grep -q 192.0.2.9", timeout=60
    )
    assert parse(client.succeed("needlecast dev show-config")).get("enabled") == "0"

    start_server(server, peer="client")
    client.succeed("umount /etc/hosts")
    client.succeed("systemctl restart nscd.service || true")
    client.wait_until_succeeds(f"getent ahostsv4 server | grep -q {real}", timeout=60)
    wait_enabled(client)
    ep = client.succeed(f"wg show {IFACE} endpoints").strip()
    print(f"endpoint after re-resolution: {ep}")
    assert real in ep, ep
    assert local(client, PORT).get("data") == "server-side"

# Otherwise a suspended laptop holds a thread until TCP keepalive notices, in two hours.
with subtest("the server reaps a client that stopped speaking"):
    before = int(server.succeed(
        "ss -tn state established | grep -c ':47653' || true").strip())
    print(f"control connections before: {before}")
    assert before >= 1

    client.succeed("systemctl kill -s SIGSTOP ncclient.service")
    # A generous multiple of the slowest heartbeat, so this takes minutes.
    server.wait_until_succeeds(
        "test \"$(ss -tn state established | grep -c ':47653' || true)\" = 0", timeout=240
    )
    print("the server closed the stalled connection")
    client.succeed("systemctl kill -s SIGCONT ncclient.service")
    wait_enabled(client)

with subtest("a clean exit on both sides leaves no trace"):
    for m in (client, server):
        unit = "ncclient" if m == client else "ncserver"
        m.succeed(f"systemctl stop {unit}.service")
        m.wait_until_fails(f"ip link show {IFACE}", timeout=30)
        m.fail(f"test -e /proc/sys/net/ipv4/conf/{IFACE}/route_localnet")
    # And behaves exactly as if needlecast were not installed.
    r = local(client, PORT, "--timeout 10")
    assert r.get("error") == "ECONNREFUSED", r
    assert client.succeed("bpftool prog show | grep -c cgroup_sock_addr || true").strip() == "0"
