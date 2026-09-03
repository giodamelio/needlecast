{
  pkgs,
  testers,
  needlecast,
  kernelPackages,
  variant,
}: let
  nodes = import ./lib/nodes.nix {inherit pkgs needlecast kernelPackages;};
  probe = import ./lib/probe.nix {inherit pkgs;};

  # Built locally so the test never needs a registry. The runtime closure of the probe pulls in
  # python3, which its shebang points at.
  image = pkgs.dockerTools.buildLayeredImage {
    name = "nc-probe";
    tag = "test";
    contents = [probe pkgs.busybox];
    config.Cmd = ["/bin/sh"];
  };
in
  testers.runNixOSTest {
    name = "needlecast-isolation-${variant}";

    nodes.laptop = {...}: {
      imports = [nodes.laptop];
      environment.systemPackages = [probe];
      virtualisation.podman.enable = true;
      virtualisation.diskSize = 4096;
    };

    testScript = ''
      KERNEL_VERSION = "${kernelPackages.kernel.version}"
      IMAGE = "${image}"
      ${builtins.readFile ./isolation.py}
    '';
  }
