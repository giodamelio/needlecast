def assert_kernel(*machines):
    """So a passing run is unambiguous about what it proved."""
    for m in machines:
        k = m.succeed("uname -r").strip()
        print(f"kernel under test: {k}")
        assert k.startswith(KERNEL_VERSION), k

def parse(out):
    d = {}
    for line in out.strip().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v
    return d

def counters(m, cmd):
    return {k: int(v) for k, v in parse(m.succeed(f"needlecast dev {cmd} || true")).items()}

def parse_keys(out):
    """`needlecast keys` prints `role base64` per line."""
    d = {}
    for line in out.strip().splitlines():
        role, key = line.split()
        d[role] = key
    return d

def place_secret(m):
    m.succeed(f"printf %s '{SECRET_TEXT}' > {SECRET}")
    m.succeed(f"chmod 600 {SECRET}")

def start_server(m, peer="client", extra="", unit="ncserver"):
    place_secret(m)
    m.succeed("rm -f /run/needlecast/server.ready")
    m.succeed(
        f"systemd-run --unit={unit} --collect "
        f"needlecast server {SECRET} {peer} --port-lo {PORT_LO} --port-hi {PORT_HI} {extra}"
    )
    try:
        m.wait_until_succeeds("test -e /run/needlecast/server.ready", timeout=60)
    except Exception:
        print(m.succeed(f"journalctl -u {unit}.service --no-pager || true"))
        raise

def start_client(m, peer="server", extra="", unit="ncclient"):
    place_secret(m)
    m.succeed("rm -f /run/needlecast/client.ready")
    m.succeed(
        f"systemd-run --unit={unit} --collect "
        f"needlecast client {SECRET} {peer} {extra}"
    )
    try:
        m.wait_until_succeeds("test -e /run/needlecast/client.ready", timeout=60)
    except Exception:
        print(m.succeed(f"journalctl -u {unit}.service --no-pager || true"))
        raise

def wait_enabled(m, timeout=90):
    """Counter assertions mean nothing while disabled: every branch but `disabled` goes
    uncounted."""
    try:
        m.wait_until_succeeds(
            "needlecast dev show-config | grep -q 'enabled=1'", timeout=timeout
        )
    except Exception:
        print(m.succeed("journalctl -u ncclient.service --no-pager | tail -40 || true"))
        raise

def serve(m, name, port, token, extra="", bind="127.0.0.1"):
    m.succeed(
        f"systemd-run --unit={name} --collect "
        f"nc-probe serve --bind {bind} --port {port} --token {token} {extra}"
    )

# The entire point: no assertion ever names the server's address.
def local(m, port, extra=""):
    return parse(m.succeed(f"nc-probe connect --host 127.0.0.1 --port {port} {extra} || true"))
