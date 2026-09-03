PORT = 8080

start_all()
for m in (server, client):
    m.wait_for_unit("multi-user.target")

assert_kernel(server, client)

with subtest("both units come up on their own"):
    server.wait_for_unit("needlecast-server.service")
    client.wait_for_unit("needlecast-client.service")
    server.wait_until_succeeds(f"ip link show {IFACE}", timeout=60)
    client.wait_until_succeeds(f"ip link show {IFACE}", timeout=60)

with subtest("the secret is read through a credential, not from the store"):
    # Never on the command line, so `ps` cannot leak the path.
    unit = client.succeed("systemctl cat needlecast-client.service")
    print(unit)
    assert "LoadCredential=secret:" in unit, unit
    assert "CREDENTIALS_DIRECTORY" in unit, unit
    assert "/nix/store" not in client.succeed(
        "systemctl show -p ExecStart needlecast-client.service | grep -o '/var/lib[^ ]*' || true"
    )

with subtest("a version mismatch would be stationary rather than a crash loop"):
    for m, unit in ((server, "needlecast-server"), (client, "needlecast-client")):
        out = m.succeed(f"systemctl show -p RestartPreventExitStatus {unit}.service")
        print(out.strip())
        assert "78" in out, out

# Behavioural rather than grepping a ruleset, which would bind this to one backend and say
# nothing about whether traffic flows.
with subtest("a port outside the managed range is not reachable over the tunnel"):
    # Reachable on the tunnel address if anything lets it through, and outside the range so
    # nothing should. Trusting the interface would quietly make this succeed.
    server.succeed(
        "systemd-run --unit=outside --collect "
        "nc-probe serve --bind 0.0.0.0 --port 9500 --token should-not-be-reachable --hold 60"
    )
    server.wait_until_succeeds("ss -lnt | grep -q '0.0.0.0:9500'", timeout=30)
    r = parse(client.succeed(
        f"nc-probe connect --host {SERVER_ADDR} --port 9500 --timeout 8 || true"
    ))
    print(f"a 0.0.0.0 service outside the range: {r}")
    assert r.get("data") != "should-not-be-reachable", r

with subtest("the tunnel forms and forwarding works"):
    client.wait_until_succeeds(f"ping -c1 -W2 {SERVER_ADDR}", timeout=90)
    server.succeed(
        "systemd-run --unit=dev --collect "
        f"nc-probe serve --bind 127.0.0.1 --port {PORT} --token via-module --hold 120"
    )
    server.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
    client.wait_until_succeeds(
        "needlecast status --role client | grep -q 'state=connected'", timeout=90
    )
    r = parse(client.succeed(
        f"nc-probe connect --host 127.0.0.1 --port {PORT} || true"
    ))
    print(r)
    assert r.get("data") == "via-module", r
    assert r.get("peer") == f"127.0.0.1:{PORT}", r

with subtest("the module's port range is what the client adopts"):
    cfg = parse(client.succeed("needlecast dev show-config"))
    assert cfg.get("port_lo") == str(PORT_LO), cfg
    assert cfg.get("port_hi") == str(PORT_HI), cfg

with subtest("systemd restarts the daemon and it comes back"):
    client.succeed("systemctl kill -s SIGKILL needlecast-client.service")
    client.wait_until_succeeds(
        "needlecast status --role client | grep -q 'state=connected'", timeout=90
    )
    r = parse(client.succeed(
        f"nc-probe connect --host 127.0.0.1 --port {PORT} || true"
    ))
    assert r.get("data") == "via-module", r

with subtest("stopping the units leaves no trace"):
    client.succeed("systemctl stop needlecast-client.service")
    client.wait_until_fails(f"ip link show {IFACE}", timeout=30)
    server.succeed("systemctl stop needlecast-server.service")
    server.wait_until_fails(f"ip link show {IFACE}", timeout=30)
    server.fail(f"test -e /proc/sys/net/ipv4/conf/{IFACE}/route_localnet")
