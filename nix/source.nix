{lib}: let
  ignored = [".direnv" ".git" ".jj" "result" "target" "nix" "tests"];
in
  lib.cleanSourceWith {
    name = "needlecast-source";
    src = ../.;
    filter = path: type: let
      base = baseNameOf path;
    in
      !(builtins.elem base ignored) && lib.cleanSourceFilter path type;
  }
