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
  # Driven exactly as a person would: two commands, one secret, a machine name each.
  testers.runNixOSTest {
    name = "needlecast-endtoend-${variant}";

    nodes.server = {...}: common;
    nodes.client = {...}: common;

    testScript = ''
      ${s.preamble kernelPackages}
      ${builtins.readFile ./endtoend.py}
    '';
  }
