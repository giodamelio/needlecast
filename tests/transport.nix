{
  pkgs,
  testers,
  needlecast,
  kernelPackages,
  variant,
}: let
  s = import ./lib/scenarios.nix {inherit pkgs;};
  common = s.node {inherit kernelPackages needlecast;};
in
  # No WireGuard is declared anywhere here: needlecast creates the tunnel from nothing but a secret
  # and a machine name.
  testers.runNixOSTest {
    name = "needlecast-transport-${variant}";

    nodes.server = {...}: common;
    nodes.client = {...}: common;

    testScript = ''
      ${s.preamble kernelPackages}
      ${builtins.readFile ./transport.py}
    '';
  }
