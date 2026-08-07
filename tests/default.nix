{
  pkgs,
  needlecast,
  needlecast-testing,
  module,
}: let
  inherit (pkgs.lib) concatMapAttrs;

  # 6.18 is the target; latest is a forward-compatibility check. A helper permitted in one and not
  # the other would otherwise show up only on the machine you actually run.
  kernels = {
    "6_18" = pkgs.linuxKernel.packages.linux_6_18;
    latest = pkgs.linuxPackages_latest;
  };

  perKernel = f:
    concatMapAttrs (variant: kernelPackages: f variant kernelPackages) kernels;

  # The shipped binary, so nothing feature-gated can be load bearing for what these prove.
  productSuites = {
    transport = ./transport.nix;
    endtoend = ./endtoend.nix;
    control = ./control.nix;
    hostile = ./hostile.nix;
    status = ./status.nix;
    resilience = ./resilience.nix;
  };

  # One half in isolation, which the shipped binary deliberately cannot do.
  harnessSuites = {
    laptop = ./laptop.nix;
    isolation = ./isolation.nix;
  };
in
  concatMapAttrs (suite: path:
    perKernel (variant: kernelPackages: {
      "${suite}-${variant}" =
        pkgs.callPackage path {inherit needlecast kernelPackages variant;};
    }))
  productSuites
  # From the module rather than `systemd-run` — the only thing that proves the two agree.
  // perKernel (variant: kernelPackages: {
    "module-${variant}" =
      pkgs.callPackage ./module.nix {inherit needlecast kernelPackages variant module;};
  })
  # The thing you boot rather than a regression net, so one kernel is enough.
  // {
    demo = pkgs.callPackage ./demo.nix {
      inherit needlecast module;
      kernelPackages = kernels."6_18";
      variant = "6_18";
    };
  }
  // concatMapAttrs (suite: path:
    perKernel (variant: kernelPackages: {
      "${suite}-${variant}" = pkgs.callPackage path {
        needlecast = needlecast-testing;
        inherit kernelPackages variant;
      };
    }))
  harnessSuites
  # The same assertions over both transports, so it is one variable changed rather than a second
  # test. The ethernet variant is the only coverage of the ARPHRD_ETHER L3 offset.
  // concatMapAttrs (transport: _:
    perKernel (variant: kernelPackages: {
      "datapath-${transport}-${variant}" = pkgs.callPackage ./datapath.nix {
        needlecast = needlecast-testing;
        inherit kernelPackages variant transport;
      };
    })) {
    ethernet = null;
    wireguard = null;
  }
