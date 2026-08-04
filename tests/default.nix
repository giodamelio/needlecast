{
  pkgs,
  needlecast-poc,
}: let
  inherit (pkgs.lib) concatMapAttrs;

  # 6.18 is the kernel this is actually developed against; latest is a forward-compatibility check.
  # Both must pass — a helper being permitted in one and not the other is exactly the kind of thing
  # that would otherwise only show up on the target machine.
  kernels = {
    "6_18" = pkgs.linuxKernel.packages.linux_6_18;
    latest = pkgs.linuxPackages_latest;
  };

  perKernel = f:
    concatMapAttrs (variant: kernelPackages: f variant kernelPackages) kernels;

  # Suites that need only one machine, plus the end-to-end one that needs two but is not
  # parameterised by transport — it only makes sense over the real tunnel.
  simpleSuites = {
    phase2 = ./phase2.nix;
    isolation = ./isolation.nix;
    endtoend = ./endtoend.nix;
    control = ./control.nix;
    hostile = ./hostile.nix;
  };
in
  concatMapAttrs (suite: path:
    perKernel (variant: kernelPackages: {
      "${suite}-${variant}" =
        pkgs.callPackage path {inherit needlecast-poc kernelPackages variant;};
    }))
  simpleSuites
  # The desktop datapath runs the same assertions over plain ethernet and over WireGuard, so
  # Phase 4 is Phase 3 with one variable changed rather than a second test.
  // concatMapAttrs (transport: _:
    perKernel (variant: kernelPackages: {
      "desktop-${transport}-${variant}" = pkgs.callPackage ./desktop.nix {
        inherit needlecast-poc kernelPackages variant transport;
      };
    })) {
    ethernet = null;
    wireguard = null;
  }
