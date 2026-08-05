{lib}: let
  root = ../.;
  # Matched against the path relative to the repo root, not the basename: `tests/` at the top level
  # is the NixOS suites, which no Rust build needs, but `crates/*/tests/` is the Rust integration
  # tests, which every Rust build does.
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
      # The design documents at the top level are not build inputs. Leaving them in would make
      # every edit to a comment rebuild the package and, through it, all twenty-two VM tests.
      isTopLevelDoc = !(lib.hasInfix "/" rel) && lib.hasSuffix ".md" rel;
    in
      !(builtins.elem rel ignored) && !isTopLevelDoc && lib.cleanSourceFilter path type;
  }
