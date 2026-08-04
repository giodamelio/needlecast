{
  lib,
  stdenv,
  rustPlatform,
  cargo,
  rustc,
  bpf-linker,
}:
stdenv.mkDerivation {
  pname = "needlecast-ebpf";
  version = "0.1.0";

  src = import ./source.nix {inherit lib;};

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ../ebpf/Cargo.lock;
  };
  cargoRoot = "ebpf";

  nativeBuildInputs = [
    rustPlatform.cargoSetupHook
    cargo
    rustc
    bpf-linker
  ];

  # nixpkgs rustc is stable and already ships a prebuilt core for bpfel-unknown-none, so the only
  # thing missing is aya-ebpf's one nightly feature.
  # The target and rustflags come from ebpf/.cargo/config.toml, which cargoSetupHook preserves.
  RUSTC_BOOTSTRAP = "1";

  buildPhase = ''
    runHook preBuild
    (cd ebpf && cargo build --release --offline --target bpfel-unknown-none)
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib
    cp ebpf/target/bpfel-unknown-none/release/needlecast $out/lib/needlecast.o
    runHook postInstall
  '';

  dontFixup = true;

  meta = {
    description = "needlecast BPF programs";
    platforms = lib.platforms.linux;
  };
}
