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
  # Both sides must degrade to "as if needlecast were not installed" and recover unattended. These
  # cases need something to actually break, so the happy-path suites cannot reach them.
  testers.runNixOSTest {
    name = "needlecast-resilience-${variant}";

    nodes.server = {...}: common;
    nodes.client = {...}: common;

    testScript = ''
      ${s.preamble kernelPackages}
      ${builtins.readFile ./resilience.py}
    '';
  }
