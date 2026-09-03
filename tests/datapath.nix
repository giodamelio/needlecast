{
  pkgs,
  testers,
  needlecast,
  kernelPackages,
  variant,
  transport,
}: let
  probe = import ./lib/probe.nix {inherit pkgs;};
  transports = import ./lib/transport.nix {inherit pkgs;};
  t = transports.${transport};

  common = {
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
    ];
  };
in
  testers.runNixOSTest {
    name = "needlecast-datapath-${transport}-${variant}";

    nodes.laptop = {...}: {imports = [common t.laptop];};
    nodes.desktop = {...}: {imports = [common t.desktop];};

    testScript = ''
      KERNEL_VERSION = "${kernelPackages.kernel.version}"
      TRANSPORT = "${transport}"
      IFACE = "${t.iface}"
      LAPTOP = "${t.laptopAddr}"
      DESKTOP = "${t.desktopAddr}"
      LAPTOP6 = "${t.laptopAddr6}"
      DESKTOP6 = "${t.desktopAddr6}"
      MTU = ${toString t.mtu}
      ${builtins.readFile ./datapath.py}
    '';
  }
