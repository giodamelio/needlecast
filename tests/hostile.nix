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
  # Every case here is a way the system could be wrong without a happy-path test noticing.
  testers.runNixOSTest {
    name = "needlecast-hostile-${variant}";

    nodes.server = {...}: common;
    nodes.client = {...}: common;

    testScript = ''
      ${s.preamble kernelPackages}
      ${builtins.readFile ./hostile.py}
    '';
  }
