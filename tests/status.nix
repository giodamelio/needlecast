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
  # No IPC dependency on the daemon, because the moment it is worth having is the moment the daemon
  # is wedged. Each of the four states is reached for real rather than simulated.
  testers.runNixOSTest {
    name = "needlecast-status-${variant}";

    nodes.server = {...}: common;
    nodes.client = {...}: common;

    testScript = ''
      ${s.preamble kernelPackages}
      ${builtins.readFile ./status.py}
    '';
  }
