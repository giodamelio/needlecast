{
  pkgs,
  testers,
  needlecast,
  kernelPackages,
  variant,
  module,
}: let
  s = import ./lib/scenarios.nix {inherit pkgs;};

  # Before the unit starts and out of the store, as a real installation has it.
  placeSecret = ''
    install -Dm600 /dev/null /var/lib/needlecast/secret
    printf %s '${s.secretText}' > /var/lib/needlecast/secret
  '';

  common = {
    imports = [module];
    boot.kernelPackages = kernelPackages;
    networking.firewall.enable = true; # the module is expected to open its own port
    virtualisation.vlans = [1];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    environment.systemPackages = with pkgs; [s.probe iproute2 wireguard-tools curl];
    system.activationScripts.needlecastSecret.text = placeSecret;
  };
in
  # `systemd-run` elsewhere cannot catch a module passing a flag the binary does not have.
  testers.runNixOSTest {
    name = "needlecast-module-${variant}";

    nodes.server = {...}: {
      imports = [common];
      services.needlecast.server = {
        enable = true;
        peer = "client";
        secretFile = "/var/lib/needlecast/secret";
        portRange = {
          from = s.portLo;
          to = s.portHi;
        };
      };
    };

    nodes.client = {...}: {
      imports = [common];
      services.needlecast.client = {
        enable = true;
        peer = "server";
        secretFile = "/var/lib/needlecast/secret";
      };
    };

    testScript = ''
      ${s.preamble kernelPackages}
      ${builtins.readFile ./module.py}
    '';
  }
