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
      needlecast-poc = pkgs.callPackage ./nix/poc.nix {inherit needlecast-ebpf;};
      default = needlecast-poc;
    });

    checks = forLinuxSystems (pkgs:
      import ./tests {
        inherit pkgs;
        needlecast-poc = self.packages.${pkgs.stdenv.hostPlatform.system}.needlecast-poc;
      });

    formatter = forAllSystems (pkgs: pkgs.alejandra);
  };
}
