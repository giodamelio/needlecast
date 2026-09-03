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
  #
  # Two pieces: the values nix generates, then `preamble.py`, which nix cannot interpolate into.
  # That split is deliberate — it keeps the generated part small and explicit, and leaves the
  # helpers as a file an editor understands.
  preamble = kernelPackages: ''
    KERNEL_VERSION = "${kernelPackages.kernel.version}"
    IFACE = "${iface}"
    SERVER_ADDR = "${serverAddr}"
    CLIENT_ADDR = "${clientAddr}"
    MTU = ${toString mtu}
    PORT_LO = ${toString portLo}
    PORT_HI = ${toString portHi}
    SECRET = "${secretPath}"
    SECRET_TEXT = "${secretText}"
    SERVER_PUBKEY = "${serverPublicKey}"
    CLIENT_PUBKEY = "${clientPublicKey}"

    ${builtins.readFile ./preamble.py}
  '';
}
