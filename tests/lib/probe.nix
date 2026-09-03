{pkgs}:
# Reports what the kernel tells the *application* — which server answered, and what
# getpeername()/recvfrom() say the peer was — because that is what the BPF programs shape.
#
# The body is a `.py` file so an editor and a linter can see it. Nix cannot interpolate into it,
# which is the point: the only generated part is the interpreter.
pkgs.writeScriptBin "nc-probe" ''
  #!${pkgs.python3}/bin/python3
  ${builtins.readFile ./probe.py}
''
