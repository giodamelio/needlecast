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
  # Liveness is the load-bearing job: without it the client keeps rewriting toward a server that is
  # gone, and connections hang on SYN retransmit instead of failing.
  testers.runNixOSTest {
    name = "needlecast-control-${variant}";

    nodes.server = {...}: common;
    nodes.client = {...}: common;

    testScript = ''
      ${s.preamble kernelPackages}
      ${builtins.readFile ./control.py}
    '';
  }
