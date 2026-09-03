PORT = 8080

start_all()
for m in (server, client):
    m.wait_for_unit("multi-user.target")

assert_kernel(server, client)

def status(m, role):
    return parse(m.succeed(f"needlecast status --role {role}"))

with subtest("never started: nothing on disk, nothing loaded, no interface"):
    st = status(client, "client")
    print(st)
    assert st.get("state") == "never-started", st
    assert st.get("interface") == "absent", st

with subtest("connected: both halves up and the bridge enabled"):
    serve(server, "dev", PORT, "server-side", "--hold 120")
    server.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
    start_server(server, peer="client")
    start_client(client, peer="server")
    wait_enabled(client)

    st = status(client, "client")
    print(client.succeed("needlecast status --role client"))
    assert st.get("state") == "connected", st
    assert st.get("enabled") == "1", st
    assert st.get("target") == SERVER_ADDR, st
    assert st.get("ports") == f"{PORT_LO}-{PORT_HI}", st
    assert str(PORT) in st.get("server_listeners", ""), st
    assert st.get("interface") == IFACE, st
    # The difference between "configured" and "works".
    assert st.get("handshake", "never") != "never", st

with subtest("status lists what is actually forwarded"):
    client.succeed("rm -f /tmp/held.out")
    client.succeed(
        f"setsid nc-probe connect --host 127.0.0.1 --port {PORT} --hold 60 "
        "> /tmp/held.out 2>&1 &"
    )
    client.wait_until_succeeds("grep -q '^data=' /tmp/held.out", timeout=20)
    out = client.succeed("needlecast status --role client")
    print(out)
    assert f"->{SERVER_ADDR}:{PORT}" in out, out

with subtest("the server reports its own half"):
    st = status(server, "server")
    print(server.succeed("needlecast status --role server"))
    assert st.get("state") == "connected", st
    assert st.get("peer") == CLIENT_ADDR, st
    assert str(PORT) in st.get("serving", ""), st
    assert st.get("rx_bytes") is not None, st

with subtest("disconnected: the daemon is running but the server is gone"):
    server.succeed("systemctl stop ncserver.service")
    client.wait_until_succeeds(
        "needlecast status --role client | grep -q 'state=disconnected'", timeout=60
    )
    st = status(client, "client")
    print(st)
    assert st.get("enabled") == "0", st
    # Cleared rather than left stale.
    assert st.get("server_listeners") == "", st
    # Still ours and still up: only the control connection is down.
    assert st.get("interface") == IFACE, st

with subtest("not running: the process died but its state is still on disk"):
    # A crash, so nothing gets a chance to tidy up.
    client.succeed("systemctl kill -s SIGKILL ncclient.service || true")
    client.wait_until_fails("systemctl is-active ncclient.service", timeout=30)
    # They survive the process, which is why `status` does not key on them.
    client.succeed("test -d /sys/fs/bpf/needlecast/client")
    st = status(client, "client")
    print(st)
    assert st.get("state") == "not-running", st

with subtest("status works when the daemon is dead, which is when it is worth having"):
    # The command above just succeeded with no process to ask.
    assert "cgroup_sock_addr" not in client.succeed("bpftool prog show | grep -c . || true")
    out = client.succeed("needlecast status --role client")
    assert "role=client" in out, out

with subtest("back to connected after both halves return"):
    client.succeed("systemctl reset-failed ncclient.service || true")
    start_server(server, peer="client")
    start_client(client, peer="server")
    wait_enabled(client)
    assert status(client, "client").get("state") == "connected"

with subtest("auto picks whichever halves ran here"):
    out = client.succeed("needlecast status")
    print(out)
    assert "role=client" in out, out
    assert "role=server" not in out, out
    out = server.succeed("needlecast status")
    assert "role=server" in out, out
