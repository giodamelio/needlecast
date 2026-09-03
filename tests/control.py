PORT = 8080
OTHER = 8081

start_all()
for m in (server, client):
    m.wait_for_unit("multi-user.target")

assert_kernel(server, client)

def config():
    return parse(client.succeed("needlecast dev show-config || true"))

def advertised():
    out = client.succeed(
        "bpftool map dump pinned /sys/fs/bpf/needlecast/client/DESKTOP_PORTS"
    )
    return out.count("key")

with subtest("the client starts disabled and stays that way until the server answers"):
    start_client(client, peer="server")
    assert config().get("enabled") == "0", config()
    # Stock behaviour: an instant, correct refusal rather than a hang.
    r = local(client, PORT, "--timeout 5")
    assert r.get("error") == "ECONNREFUSED", r
    print("no server: " + str(config()))

with subtest("bringing the server up enables the client on its own"):
    serve(server, "dev", PORT, "server-side")
    server.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
    start_server(server, peer="client")
    wait_enabled(client)
    r = local(client, PORT)
    assert r.get("data") == "server-side", r

with subtest("the managed range comes from the server, not from a flag on this side"):
    # Never told a range; it adopts whatever the server says it serves.
    cfg = config()
    assert cfg.get("port_lo") == str(PORT_LO), cfg
    assert cfg.get("port_hi") == str(PORT_HI), cfg

with subtest("the listener set gates ports the server does not serve"):
    before = counters(client, "counters")
    r = local(client, OTHER, "--timeout 5")
    assert r.get("error") == "ECONNREFUSED", r
    after = counters(client, "counters")
    na = after.get("connect4.not_advertised", 0) - before.get("connect4.not_advertised", 0)
    print(f"connect4.not_advertised +{na}")
    assert na >= 1, (before, after)

with subtest("a port appearing on the server becomes usable without restarting anything"):
    serve(server, "dev2", OTHER, "server-two")
    server.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{OTHER}'", timeout=30)
    client.wait_until_succeeds(
        f"nc-probe connect --host 127.0.0.1 --port {OTHER} | grep -q server-two", timeout=30
    )
    print("a new server port became usable")

with subtest("a port disappearing stops being forwarded"):
    server.succeed("systemctl stop dev2.service")
    server.wait_until_fails(f"ss -lnt | grep -q '127.0.0.1:{OTHER}'", timeout=30)
    print("the server now serves: " + server.succeed("needlecast dev listeners | tr '\n' ' '"))
    import time as _t
    for _ in range(30):
        r = local(client, OTHER, "--timeout 5")
        if r.get("error"):
            break
        _t.sleep(1)
    print(f"after withdrawal: {r}  advertised entries: {advertised()}")
    assert r.get("error") == "ECONNREFUSED", r

with subtest("killing the server disables the client and clears the listener set"):
    server.succeed("systemctl stop ncserver.service")
    client.wait_until_succeeds(
        "needlecast dev show-config | grep -q 'enabled=0'", timeout=60
    )
    # Cleared, not left stale: a stale set is worse than none.
    assert advertised() == 0, "the listener set was not cleared on disconnect"
    r = local(client, PORT, "--timeout 5")
    assert r.get("error") == "ECONNREFUSED", r

with subtest("the client reconnects on its own when the server returns"):
    start_server(server, peer="client")
    wait_enabled(client)
    r = local(client, PORT)
    assert r.get("data") == "server-side", r

with subtest("TCP_SYNCNT is applied to rewritten sockets, and only to those"):
    before = counters(client, "counters")
    local(client, PORT)
    after = counters(client, "counters")
    ok = after.get("connect4.setsockopt_ok", 0) - before.get("connect4.setsockopt_ok", 0)
    err = after.get("connect4.setsockopt_err", 0) - before.get("connect4.setsockopt_err", 0)
    rewritten = after.get("connect4.rewritten", 0) - before.get("connect4.rewritten", 0)
    print(f"rewritten +{rewritten}, setsockopt ok +{ok} err +{err}")
    assert ok == rewritten and err == 0, (before, after)

# Holding a connection open is what speeds the heartbeat up, and what makes the next subtest
# measurable in seconds rather than half a minute.
with subtest("the heartbeat speeds up while a connection is open"):
    serve(server, "held", 8088, "held-open", "--hold 120")
    server.wait_until_succeeds("ss -lnt | grep -q '127.0.0.1:8088'", timeout=30)
    client.wait_until_succeeds(
        "needlecast status --role client | grep -q 'server_listeners=.*8088'", timeout=30
    )
    client.succeed("rm -f /tmp/held.out")
    client.succeed(
        "setsid nc-probe connect --host 127.0.0.1 --port 8088 --hold 90 "
        "> /tmp/held.out 2>&1 &"
    )
    client.wait_until_succeeds("grep -q '^data=' /tmp/held.out", timeout=20)
    # The same reading the heartbeat uses to decide.
    out = client.succeed("needlecast status --role client")
    print(out)
    assert "forwarded=" in out, out

# If either half of this failed, the control plane would be forwarding itself.
with subtest("the control connection is never itself forwarded"):
    import time as _t
    # tc ingress skips it as out of range, visible as a rising counter while the heartbeat
    # runs — once a second, now that a connection is open.
    b = counters(server, "tc-counters")
    _t.sleep(6)
    a = counters(server, "tc-counters")
    delta = a.get("tc_ingress.port_out_of_range", 0) - b.get(
        "tc_ingress.port_out_of_range", 0)
    print(f"tc_ingress.port_out_of_range +{delta} while the heartbeat ran")
    assert delta >= 1, (b, a)

    # The client declines it as non-loopback. Measured across a real disconnect, since that
    # is when the control socket is created — a fast restart would not contain one.
    before = counters(client, "counters")
    server.succeed("systemctl stop ncserver.service")
    client.wait_until_succeeds(
        "needlecast dev show-config | grep -q 'enabled=0'", timeout=60
    )
    start_server(server, peer="client")
    wait_enabled(client)
    after = counters(client, "counters")
    nl = after.get("connect4.not_loopback", 0) - before.get("connect4.not_loopback", 0)
    rw = after.get("connect4.rewritten", 0) - before.get("connect4.rewritten", 0)
    print(f"across a reconnect: not_loopback +{nl}, rewritten +{rw}")
    assert nl >= 1, (before, after)
    assert rw == 0, "the control connection was rewritten"

with subtest("final config"):
    print(client.succeed("needlecast dev show-config"))
