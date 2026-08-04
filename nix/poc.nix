{
  lib,
  rustPlatform,
  needlecast-ebpf,
}:
rustPlatform.buildRustPackage {
  pname = "needlecast-poc";
  version = "0.1.0";

  src = import ./source.nix {inherit lib;};

  cargoLock.lockFile = ../Cargo.lock;

  NEEDLECAST_EBPF_OBJ = "${needlecast-ebpf}/lib/needlecast.o";

  meta = {
    description = "needlecast proof-of-concept loader and control CLI";
    mainProgram = "needlecast-poc";
    platforms = lib.platforms.linux;
  };
}
