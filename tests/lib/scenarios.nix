{pkgs}: let
  probe = import ./probe.nix {inherit pkgs;};

  # Committed deliberately: the whole network lives inside one VM test. The daemon enforces mode
  # 600, so the tests place it rather than relying on the store's permissions.
  secretText = "gCPmMEnG3ZucCkC2gzcTGKvIETyufAJXWr6zJVCKk4Q=";
in rec {
  inherit probe secretText;

  # Derived from `secretText`, cross-checked against `wg pubkey`.
  serverPublicKey = "ZVnbvcoGI3M2tQwGjUgMjlpUh7hRAZ6ve0/6iCJ0Y3Y=";
  clientPublicKey = "quNwuLJbIui3Quc9cqyXZEbtE22/YzLyou6PbbhKw1I=";

  # nixpkgs' own throwaway test keypair (RFC 9500's), so nothing secret is committed and nothing is
  # generated impurely. It lives in the store and is therefore world-readable, which `ssh` refuses —
  # `nix run .#demo-ssh` copies it to mode 600 first.
  demoSsh = let
    keys = import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs;
  in {
    inherit (keys) snakeOilPrivateKey snakeOilPublicKey;
    # Forwarded to each machine's sshd.
    ports = {
      server = 2201;
      client = 2202;
    };
  };

  iface = "needle";
  serverAddr = "198.18.0.1";
  clientAddr = "198.18.0.2";
  mtu = 1420;
  controlPort = 47653;
  listenPort = 47654;
  portLo = 8000;
  portHi = 8999;
  secretPath = "/run/needlecast.secret";

  # No WireGuard is declared anywhere: the daemon creates and owns `needle`.
  node = {
    kernelPackages,
    needlecast,
  }: {
    boot.kernelPackages = kernelPackages;
    networking.firewall.enable = false;
    virtualisation.vlans = [1];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    virtualisation.diskSize = 4096;
    environment.systemPackages = with pkgs; [
      needlecast
      probe
      bpftools
      iproute2
      python3
      tcpdump
      wireguard-tools
      curl
    ];
  };

  # Shared so the suites cannot drift. Machine *names*, not addresses: the framework assigns vlan
  # addresses in an order that is not the node declaration order.
  preamble = ''
    IFACE = "${iface}"
    SERVER_ADDR = "${serverAddr}"
    CLIENT_ADDR = "${clientAddr}"
    MTU = ${toString mtu}
    PORT_LO = ${toString portLo}
    PORT_HI = ${toString portHi}
    SECRET = "${secretPath}"
    SERVER_PUBKEY = "${serverPublicKey}"
    CLIENT_PUBKEY = "${clientPublicKey}"

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
        m.succeed(f"printf %s '${secretText}' > {SECRET}")
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
  '';

  # So a passing run is unambiguous about what it proved.
  assertKernel = kernelPackages: machines: ''
    for _m in [${builtins.concatStringsSep ", " machines}]:
        _k = _m.succeed("uname -r").strip()
        print(f"kernel under test: {_k}")
        assert _k.startswith("${kernelPackages.kernel.version}"), _k
  '';
}
