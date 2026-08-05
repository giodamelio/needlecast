{
  description = "needlecast";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    systems = ["aarch64-darwin" "aarch64-linux" "x86_64-darwin" "x86_64-linux"];
    linuxSystems = ["aarch64-linux" "x86_64-linux"];
    forAllSystems = f:
      nixpkgs.lib.genAttrs systems
      (system: f nixpkgs.legacyPackages.${system});
    forLinuxSystems = f:
      nixpkgs.lib.genAttrs linuxSystems
      (system: f nixpkgs.legacyPackages.${system});
  in {
    devShells = forAllSystems (pkgs: {
      default = pkgs.mkShell {
        packages = with pkgs; [
          cargo
          cargo-nextest
          rustc
          rustfmt
          clippy
          rust-analyzer
          bpf-linker
        ];

        RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
      };
    });

    packages = forLinuxSystems (pkgs: rec {
      needlecast-ebpf = pkgs.callPackage ./nix/ebpf.nix {};
      needlecast = pkgs.callPackage ./nix/needlecast.nix {inherit needlecast-ebpf;};
      needlecast-testing = pkgs.callPackage ./nix/needlecast.nix {
        inherit needlecast-ebpf;
        testing = true;
      };
      default = needlecast;
    });

    apps = forLinuxSystems (pkgs: rec {
      needlecast = {
        type = "app";
        program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.needlecast}/bin/needlecast";
      };
      # Two machines installed from the module, paused at the test driver's prompt so you can boot
      # them and look around. See tests/demo.nix for what to type.
      demo = {
        type = "app";
        program = "${
          self.checks.${pkgs.stdenv.hostPlatform.system}.demo.driverInteractive
        }/bin/nixos-test-driver";
      };

      # Root shell on either demo machine, once `nix run .#demo` has booted them.
      #
      #     nix run .#demo-ssh -- client
      #     nix run .#demo-ssh -- server curl -sf http://localhost:8080/hello.txt
      #
      # The key is nixpkgs' snakeoil test key, which lives in the store and is therefore
      # world-readable — `ssh` refuses such a file, so this copies it to mode 600 first.
      demo-ssh = let
        demoSsh = (import ./tests/lib/scenarios.nix {inherit pkgs;}).demoSsh;
      in {
        type = "app";
        program = "${pkgs.writeShellScript "needlecast-demo-ssh" ''
          set -eu
          case "''${1-client}" in
            server) port=${toString demoSsh.ports.server} ;;
            client) port=${toString demoSsh.ports.client} ;;
            *)
              echo "usage: nix run .#demo-ssh -- [server|client] [command...]" >&2
              exit 2
              ;;
          esac
          shift || true

          key=$(mktemp -t needlecast-demo-key.XXXXXX)
          install -m600 ${demoSsh.snakeOilPrivateKey} "$key"
          # The machines are thrown away with the driver, so pinning their host keys would only
          # produce a warning to ignore on the next boot.
          # `set -e` would abort on a failed connection and leak the key, so take the status
          # explicitly.
          rc=0
          ${pkgs.openssh}/bin/ssh \
            -i "$key" -o IdentitiesOnly=yes \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
            -p "$port" root@localhost "$@" || rc=$?
          rm -f "$key"
          exit $rc
        ''}";
      };
      default = needlecast;
    });

    # For anyone who would rather have `pkgs.needlecast` than set the option.
    overlays.default = final: _prev: {
      needlecast-ebpf = final.callPackage ./nix/ebpf.nix {};
      needlecast = final.callPackage ./nix/needlecast.nix {
        inherit (final) needlecast-ebpf;
      };
    };

    # Defaults the package from this flake rather than adding an overlay, because `nixpkgs.overlays`
    # is read-only inside a NixOS test and a module that cannot be tested is not much of a module.
    nixosModules.default = {
      pkgs,
      lib,
      ...
    }: {
      imports = [./nix/module.nix];
      services.needlecast.package =
        lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.needlecast;
    };

    checks = forLinuxSystems (pkgs:
      import ./tests {
        inherit pkgs;
        inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) needlecast needlecast-testing;
        module = self.nixosModules.default;
      });

    formatter = forAllSystems (pkgs: pkgs.alejandra);
  };
}
