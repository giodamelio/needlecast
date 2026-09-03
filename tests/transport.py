start_all()
for m in (server, client):
    m.wait_for_unit("multi-user.target")

assert_kernel(server, client)

with subtest("neither machine has an interface before needlecast runs"):
    for m in (server, client):
        m.fail(f"ip link show {IFACE}")
        # It lives and dies with the interface, so its absence proves nothing is configured.
        m.fail(f"test -e /proc/sys/net/ipv4/conf/{IFACE}/route_localnet")

with subtest("both sides derive the same two keys from the same file"):
    for m in (server, client):
        place_secret(m)
    out_s = parse_keys(server.succeed(f"needlecast keys {SECRET}"))
    out_c = parse_keys(client.succeed(f"needlecast keys {SECRET}"))
    print(f"server key {out_s['server']}, client key {out_s['client']}")
    assert out_s == out_c, (out_s, out_c)
    assert out_s["server"] == SERVER_PUBKEY, out_s
    assert out_s["client"] == CLIENT_PUBKEY, out_s

with subtest("a secret anyone else can read is refused"):
    server.succeed(f"chmod 644 {SECRET}")
    err = server.fail(f"needlecast keys {SECRET} 2>&1")
    assert "readable by someone other than its owner" in err, err
    server.succeed(f"chmod 600 {SECRET}")

with subtest("needlecast creates and configures the interface itself"):
    start_server(server, peer="client")
    start_client(client, peer="server")

    for m, want, peer_key in (
        (server, SERVER_ADDR, CLIENT_PUBKEY),
        (client, CLIENT_ADDR, SERVER_PUBKEY),
    ):
        link = m.succeed(f"ip -4 addr show {IFACE}")
        print(link)
        assert f"inet {want}/24" in link, link
        assert f"mtu {MTU}" in link, link
        assert "UP" in link, link
        wg = m.succeed(f"wg show {IFACE}")
        print(wg)
        assert peer_key in wg, wg

with subtest("the interface carries exactly the derived keys"):
    assert server.succeed(f"wg show {IFACE} public-key").strip() == SERVER_PUBKEY
    assert client.succeed(f"wg show {IFACE} public-key").strip() == CLIENT_PUBKEY

with subtest("allowed-ips is the peer alone, not the whole subnet"):
    for m, peer in ((server, CLIENT_ADDR), (client, SERVER_ADDR)):
        allowed = m.succeed(f"wg show {IFACE} allowed-ips").strip()
        print(allowed)
        assert f"{peer}/32" in allowed, allowed
        assert "/24" not in allowed, allowed

with subtest("the handshake completes and traffic crosses"):
    client.wait_until_succeeds(f"ping -c1 -W2 {SERVER_ADDR}", timeout=60)
    server.wait_until_succeeds(f"ping -c1 -W2 {CLIENT_ADDR}", timeout=60)
    hs = client.succeed(f"wg show {IFACE} latest-handshakes").strip()
    print(hs)
    assert hs.split()[-1] != "0", hs

with subtest("only the server sets route_localnet, and only on its own interface"):
    assert server.succeed(f"sysctl -n net.ipv4.conf.{IFACE}.route_localnet").strip() == "1"
    # The client delivers nothing to loopback.
    assert client.succeed(f"sysctl -n net.ipv4.conf.{IFACE}.route_localnet").strip() == "0"
    for m in (server, client):
        for key in ("all", "lo", "default"):
            assert m.succeed(f"sysctl -n net.ipv4.conf.{key}.route_localnet").strip() == "0", key

with subtest("only the client sends keepalives"):
    # The server has the stable address, so the NAT hole is the client's to hold open.
    assert "off" in server.succeed(f"wg show {IFACE} persistent-keepalive"), "server"
    assert "25" in client.succeed(f"wg show {IFACE} persistent-keepalive"), "client"

with subtest("a restart adopts a leftover interface rather than failing"):
    # Without letting it clean up, as a crash would.
    client.succeed("systemctl kill -s SIGKILL ncclient.service || true")
    client.wait_until_fails("systemctl is-active ncclient.service", timeout=30)
    client.succeed(f"ip link show {IFACE}")  # still there, as after a crash
    leftover = client.succeed(f"ip -4 addr show {IFACE}")
    print("after the crash: " + leftover.strip())

    client.succeed("systemctl reset-failed ncclient.service || true")
    start_client(client, peer="server")
    client.wait_until_succeeds(f"ping -c1 -W2 {SERVER_ADDR}", timeout=60)
    assert f"inet {CLIENT_ADDR}/24" in client.succeed(f"ip -4 addr show {IFACE}")

with subtest("a clean exit leaves no trace"):
    client.succeed("systemctl stop ncclient.service")
    client.wait_until_fails(f"ip link show {IFACE}", timeout=30)
    client.fail(f"test -e /proc/sys/net/ipv4/conf/{IFACE}/route_localnet")

    server.succeed("systemctl stop ncserver.service")
    server.wait_until_fails(f"ip link show {IFACE}", timeout=30)
    server.fail(f"test -e /proc/sys/net/ipv4/conf/{IFACE}/route_localnet")

with subtest("an unresolvable peer is survivable, not fatal"):
    # Still worth having up so the peer can reach *us* when it returns.
    start_client(client, peer="nonexistent.invalid", unit="ncorphan")
    client.succeed(f"ip link show {IFACE}")
    assert "(none)" in client.succeed(f"wg show {IFACE} endpoints") or \
           client.succeed(f"wg show {IFACE} endpoints").split()[-1] == "(none)"
    client.succeed("systemctl stop ncorphan.service")
