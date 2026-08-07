{lib}: let
  root = ../.;
  # Relative to the repo root, not by basename: top-level `tests/` is the NixOS suites, but
  # `crates/*/tests/` is the Rust integration tests.
  ignored = [
    ".direnv"
    ".git"
    ".jj"
    "result"
    "target"
    "nix"
    "tests"
  ];
  prefix = toString root + "/";
in
  lib.cleanSourceWith {
    name = "needlecast-source";
    src = root;
    filter = path: type: let
      rel = lib.removePrefix prefix (toString path);
      # Not build inputs; leaving them in makes a doc edit rebuild every VM test.
      isTopLevelDoc = !(lib.hasInfix "/" rel) && lib.hasSuffix ".md" rel;
    in
      !(builtins.elem rel ignored) && !isTopLevelDoc && lib.cleanSourceFilter path type;
  }
