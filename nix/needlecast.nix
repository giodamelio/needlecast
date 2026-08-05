{
  lib,
  rustPlatform,
  cargo-nextest,
  needlecast-ebpf,
  # Compiles the affordances the VM suites need to isolate one half of the system. Off for anything
  # that ships, so no feature-gated path can become load bearing for the real thing.
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

  # The default nextest profile in .config/nextest.toml excludes the `vm` binary, which shells out
  # to `nix build` and cannot run inside a sandbox. Everything else runs here, so a broken predicate
  # fails the package build rather than waiting for someone to run the tests by hand.
  useNextest = true;
  nativeCheckInputs = [cargo-nextest];

  NEEDLECAST_EBPF_OBJ = "${needlecast-ebpf}/lib/needlecast.o";

  meta = {
    description = "reach the other machine's localhost";
    mainProgram = "needlecast";
    platforms = lib.platforms.linux;
  };
}
