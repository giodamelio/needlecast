{
  pkgs,
  testers,
  needlecast,
  kernelPackages,
  variant,
}: let
  nodes = import ./lib/nodes.nix {inherit pkgs needlecast kernelPackages;};
  probe = import ./lib/probe.nix {inherit pkgs;};
in
  testers.runNixOSTest {
    name = "needlecast-laptop-${variant}";

    nodes.laptop = {...}: {
      imports = [nodes.laptop];
      environment.systemPackages = [probe];
    };

    testScript = ''
      KERNEL_VERSION = "${kernelPackages.kernel.version}"
      ${builtins.readFile ./laptop.py}
    '';
  }
