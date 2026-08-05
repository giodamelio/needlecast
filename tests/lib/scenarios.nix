{pkgs}: let
  probe = import ./probe.nix {inherit pkgs;};

  # One shared secret, committed deliberately: it is what the two nodes derive both keypairs from,
  # and the whole network lives inside one VM test. Mode 600 is enforced by the daemon, so the
  # tests place it rather than relying on the store's permissions.
  secretText = "gCPmMEnG3ZucCkC2gzcTGKvIETyufAJXWr6zJVCKk4Q=";
in rec {
  inherit probe secretText;

  # Both keypairs derived from `secretText`, cross-checked against `wg pubkey`. Named here so a
  # test can assert the interface really carries the derived key rather than some other one.
  serverPublicKey = "ZVnbvcoGI3M2tQwGjUgMjlpUh7hRAZ6ve0/6iCJ0Y3Y=";
  clientPublicKey = "quNwuLJbIui3Quc9cqyXZEbtE22/YzLyou6PbbhKw1I=";

  # Key-only root login for the demo VMs, using the throwaway keypair nixpkgs ships for its own
  # integration tests — RFC 9500's test key. Nothing secret is committed here, and nothing has to be
  # generated impurely.
  #
  # The private key lives in the store, which makes it world-readable, and `ssh` refuses a key file
  # anyone can read. `nix run .#demo-ssh` copies it to mode 600 first so that is not your problem.
  demoSsh = let
    keys = import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs;
  in {
    inherit (keys) snakeOilPrivateKey snakeOilPublicKey;
    # Host ports the demo forwards to each machine's sshd.
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

  # A machine that could run either half. No WireGuard is declared anywhere: the daemon creates
  # and owns `needle`, which is the point of every suite that imports this.
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

  # Python helpers every product suite needs, so the three of them cannot drift.
  #
  # Machine *names* are used for the WireGuard endpoint: the test framework assigns vlan addresses
  # in an order that is not the node declaration order, and `/etc/hosts` in a NixOS test maps every
  # machine name to its vlan address.
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
        """Counter assertions are only meaningful while the bridge is enabled: if the control
        connection blips, every branch but `disabled` goes uncounted."""
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

    # Everything the client does is addressed to plain localhost. That is the entire point: no
    # assertion here ever names the server's address.
    def local(m, port, extra=""):
        return parse(m.succeed(f"nc-probe connect --host 127.0.0.1 --port {port} {extra} || true"))
  '';

  # Record the kernel under test, so a passing run is unambiguous about what it proved.
  assertKernel = kernelPackages: machines: ''
    for _m in [${builtins.concatStringsSep ", " machines}]:
        _k = _m.succeed("uname -r").strip()
        print(f"kernel under test: {_k}")
        assert _k.startswith("${kernelPackages.kernel.version}"), _k
  '';
}
