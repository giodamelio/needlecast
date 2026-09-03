PORT = 8080
UDP_PORT = 8053

start_all()
for m in (server, client):
    m.wait_for_unit("multi-user.target")

assert_kernel(server, client)

with subtest("bring both halves up"):
    start_server(server, peer="client")
    start_client(client, peer="server")
    print(server.succeed("cat /run/needlecast/server.ready"))
    print(client.succeed("cat /run/needlecast/client.ready"))

with subtest("localhost:8080 on the client reaches the server's dev server"):
    serve(server, "dev", PORT, "server-side", "--hold 120")
    server.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
    wait_enabled(client)

    before_c = counters(client, "counters")
    before_s = counters(server, "tc-counters")
    r = local(client, PORT)
    assert r.get("data") == "server-side", r
    # The port the user typed is preserved end to end, never translated.
    assert r.get("peer") == f"127.0.0.1:{PORT}", r

    after_c = counters(client, "counters")
    after_s = counters(server, "tc-counters")
    assert after_c.get("connect4.rewritten", 0) > before_c.get("connect4.rewritten", 0)
    assert after_c.get("getpeername4.restored", 0) > before_c.get("getpeername4.restored", 0)
    assert after_s.get("tc_ingress.rewritten_tcp", 0) > before_s.get(
        "tc_ingress.rewritten_tcp", 0)
    assert after_s.get("tc_egress.rewritten_tcp", 0) > before_s.get(
        "tc_egress.rewritten_tcp", 0)

with subtest("both ends believe they are talking to loopback"):
    # Held open at both ends, or the socket is gone before the kernel view can be read.
    client.succeed("rm -f /tmp/held.out")
    client.succeed(
        f"setsid nc-probe connect --host 127.0.0.1 --port {PORT} --hold 60 "
        "> /tmp/held.out 2>&1 &"
    )
    client.wait_until_succeeds("grep -q '^data=' /tmp/held.out", timeout=20)
    seen_by_client = parse(client.succeed("cat /tmp/held.out"))

    server.wait_until_succeeds(
        "journalctl -u dev --no-pager | grep -q accepted_peer=", timeout=15
    )
    line = server.succeed(
        "journalctl -u dev --no-pager | grep accepted_peer= | tail -1"
    ).strip()
    seen_by_server = line.split("accepted_peer=")[1].rsplit(":", 1)[0]
    print(f"client was told {seen_by_client.get('peer')}; server was told {seen_by_server}")
    assert seen_by_client.get("peer") == f"127.0.0.1:{PORT}", seen_by_client
    assert seen_by_server == "127.0.0.1", line

    # Meanwhile the kernel on each side records the truth, which is what makes this
    # debuggable rather than mysterious.
    est = server.succeed(f"ss -tn state established | grep '127.0.0.1:{PORT} '")
    print("server kernel view: " + est.strip())
    assert CLIENT_ADDR in est, est
    cest = client.succeed(f"ss -tn state established | grep ':{PORT}'")
    print("client kernel view: " + cest.strip())
    assert SERVER_ADDR in cest, cest

with subtest("a client-local listener wins over the server"):
    serve(client, "locallistener", PORT, "client-local")
    client.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
    before = counters(client, "counters")
    r = local(client, PORT)
    assert r.get("data") == "client-local", r
    after = counters(client, "counters")
    assert after.get("connect4.local_listener", 0) > before.get("connect4.local_listener", 0)
    assert after.get("connect4.rewritten", 0) == before.get("connect4.rewritten", 0)

with subtest("removing it hands the port back to the server"):
    client.succeed("systemctl stop locallistener.service")
    client.wait_until_fails(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
    r = local(client, PORT)
    assert r.get("data") == "server-side", r

with subtest("UDP works end to end"):
    serve(server, "udpdev", UDP_PORT, "server-udp", "--udp")
    server.wait_until_succeeds(f"ss -lnu | grep -q '127.0.0.1:{UDP_PORT}'", timeout=30)
    client.wait_until_succeeds(
        f"needlecast status --role client | grep -q 'server_listeners=.*{UDP_PORT}'",
        timeout=30,
    )
    before = counters(client, "counters")
    r = local(client, UDP_PORT, "--udp --unconnected")
    assert r.get("data", "").startswith("server-udp"), r
    assert r.get("peer") == f"127.0.0.1:{UDP_PORT}", r
    after = counters(client, "counters")
    assert after.get("sendmsg4.rewritten", 0) > before.get("sendmsg4.rewritten", 0)
    assert after.get("recvmsg4.restored", 0) > before.get("recvmsg4.restored", 0)

with subtest("a large UDP datagram survives the whole chain"):
    r = local(client, UDP_PORT, f"--udp --unconnected --payload-size {MTU * 4} --timeout 30")
    assert r.get("echo_ok") == "True", r

with subtest("a bulk transfer survives the whole chain"):
    server.succeed("head -c 209715200 /dev/urandom > /tmp/blob")
    want = server.succeed("sha256sum /tmp/blob").split()[0]
    serve(server, "bulk", 8082, "unused", "--file /tmp/blob")
    server.wait_until_succeeds("ss -lnt | grep -q '127.0.0.1:8082'", timeout=30)
    client.wait_until_succeeds(
        "needlecast status --role client | grep -q 'server_listeners=.*8082'", timeout=30
    )
    r = local(client, 8082, "--out /tmp/blob --timeout 300")
    assert int(r["bytes"]) == 209715200, r
    assert client.succeed("sha256sum /tmp/blob").split()[0] == want

# The v6 half of the same claim, and the only end-to-end coverage of the loopback redirect: the
# client rewrites `::1` at connect(), the server delivers to `::1`, and neither application ever
# sees a tunnel address.
with subtest("[::1]:8080 on the client reaches the server's v6 dev server"):
    V6_PORT = 8070
    serve(server, "dev6", V6_PORT, "server-side-v6", "--v6 --hold 120", bind="::1")
    server.wait_until_succeeds(f"ss -lnt | grep -q ':{V6_PORT}'", timeout=30)
    client.wait_until_succeeds(
        f"needlecast status --role client | grep -q 'server_listeners=.*{V6_PORT}'", timeout=60
    )
    r = local6(client, V6_PORT)
    print(f"v6 end to end: {r}")
    assert r.get("data") == "server-side-v6", r

with subtest("both applications still believe the peer is loopback over v6"):
    assert local6(client, V6_PORT).get("peer", "").startswith("::1"), "the client's view"
    c = counters(client, "counters")
    assert c.get("connect6.rewritten", 0) >= 1, c
    assert c.get("getpeername6.restored", 0) >= 1, c
    assert c.get("connect6.no_v6_target", 0) == 0, c

with subtest("a v6 port the server does not serve fails cleanly rather than hanging"):
    r = local6(client, 8091, "--timeout 15")
    assert r.get("error") == "ECONNREFUSED", r

with subtest("a port the server does not serve fails, and does not hang"):
    r = local(client, 8090, "--timeout 15")
    print(f"unserved port: {r}")
    assert r.get("error") == "ECONNREFUSED", r

with subtest("stopping the client reverts everything"):
    client.succeed("systemctl stop ncclient.service")
    r = local(client, PORT, "--timeout 10")
    assert r.get("error") == "ECONNREFUSED", r
    client.wait_until_fails(f"ip link show {IFACE}", timeout=30)

with subtest("final counters"):
    start_client(client, peer="server")
    wait_enabled(client)
    local(client, PORT)
    print("--- client ---")
    print(client.succeed("needlecast dev counters"))
    print("--- server ---")
    print(server.succeed("needlecast dev tc-counters"))
