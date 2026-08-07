{
  lib,
  rustPlatform,
  cargo-nextest,
  needlecast-ebpf,
  # The affordances the VM suites need to isolate one half. Off for anything that ships.
  testing ? false,
}:
rustPlatform.buildRustPackage {
  pname =
    if testing
    then "needlecast-testing"
    else "needlecast";
  version = "0.1.0";

  src = import ./source.nix {inherit lib;};

  cargoLock.lockFile = ../Cargo.lock;

  buildFeatures = lib.optional testing "testing";

  # The default nextest profile excludes the `vm` binary, which shells out to `nix build`.
  # Everything else runs here, so a broken predicate fails the package build.
  useNextest = true;
  nativeCheckInputs = [cargo-nextest];

  NEEDLECAST_EBPF_OBJ = "${needlecast-ebpf}/lib/needlecast.o";

  meta = {
    description = "reach the other machine's localhost";
    mainProgram = "needlecast";
    platforms = lib.platforms.linux;
  };
}
