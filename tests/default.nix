{
  pkgs,
  needlecast,
  needlecast-testing,
  module,
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

  # Suites that drive the shipped binary — the product surface, secret file and all. Nothing
  # feature-gated can be load bearing for anything proved here.
  productSuites = {
    transport = ./transport.nix;
    endtoend = ./endtoend.nix;
    control = ./control.nix;
    hostile = ./hostile.nix;
    status = ./status.nix;
    resilience = ./resilience.nix;
  };

  # Suites that isolate one half of the system, which the shipped binary deliberately cannot do.
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
  # The module suite builds its nodes from the module rather than from `systemd-run`, which is the
  # only thing that proves the module and the daemon's flags agree.
  // perKernel (variant: kernelPackages: {
    "module-${variant}" =
      pkgs.callPackage ./module.nix {inherit needlecast kernelPackages variant module;};
  })
  # The demo is the thing you boot, not a regression net: it duplicates what `module` already
  # asserts, so it runs on the target kernel only.
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
  # The datapath runs the same assertions over plain ethernet and over WireGuard, so the transport
  # is one variable changed rather than a second test. Both use the testing build: the ethernet
  # variant is the only coverage of the ARPHRD_ETHER L3 offset, which the product never sees.
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
