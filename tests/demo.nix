{
  pkgs,
  testers,
  needlecast,
  kernelPackages,
  variant,
  module,
}: let
  s = import ./lib/scenarios.nix {inherit pkgs;};

  # A real installation has the secret on disk before the unit starts, out of the store. This is
  # the same constraint, met the same way.
  placeSecret = ''
    install -Dm600 /dev/null /var/lib/needlecast/secret
    printf %s '${s.secretText}' > /var/lib/needlecast/secret
  '';

  # Host ports you can reach the two machines on while the driver is paused, and the throwaway key
  # that gets you in. Shared with `nix run .#demo-ssh`, so the two cannot disagree.
  inherit (s.demoSsh) ports snakeOilPublicKey;

  common = name: {
    imports = [module];
    boot.kernelPackages = kernelPackages;
    # On, because a real machine has it on, and because needlecast having to ask for what it needs
    # is part of what this is demonstrating.
    networking.firewall.enable = true;
    virtualisation.vlans = [1];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    virtualisation.forwardPorts = [
      {
        from = "host";
        host.port = ports.${name};
        guest.port = 22;
      }
    ];

    # Key only, so there is no password to get wrong and none to leave enabled by accident. The
    # test framework gives root an empty `hashedPasswordFile` that would otherwise win over anything
    # set here, which is its own reason not to go the password route.
    services.openssh = {
      enable = true;
      settings.PermitRootLogin = "prohibit-password";
    };
    users.users.root.openssh.authorizedKeys.keys = [snakeOilPublicKey];

    environment.systemPackages = with pkgs; [
      curl
      iproute2
      wireguard-tools
      tcpdump
      python3
      s.probe
    ];
    system.activationScripts.needlecastSecret.text = placeSecret;
  };
in
  # The smallest thing that is still a real installation: two machines, one secret, the module on
  # both, and a dev server the other side reaches as `localhost`. Everything else in `tests/` is
  # trying to catch a specific way this could be wrong; this one is just the thing working.
  #
  # To poke at it:
  #
  #     nix run .#demo
  #     >>> start_all()                      # only what you type runs; the script below does not
  #     >>> client.shell_interact()          # a root shell on the console
  #
  # or, from another terminal once `start_all()` has run:
  #
  #     nix run .#demo-ssh -- client
  #     nix run .#demo-ssh -- server
  #     nix run .#demo-ssh -- client curl -sf http://localhost:8080/hello.txt
  testers.runNixOSTest {
    name = "needlecast-demo-${variant}";

    nodes.server = {...}: {
      imports = [(common "server")];
      services.needlecast.server = {
        enable = true;
        peer = "client";
        secretFile = "/var/lib/needlecast/secret";
      };

      # The thing worth reaching: an ordinary dev server, bound to loopback exactly as you would
      # bind one, with no idea needlecast exists.
      systemd.services.devserver = {
        wantedBy = ["multi-user.target"];
        # Declared here rather than written by the test script: in interactive mode the script does
        # not run, and a demo whose one interesting file only exists under `nix flake check` would
        # be useless at exactly the moment you booted it to look around.
        preStart = ''
          mkdir -p /var/www
          echo "hello from the other machine" > /var/www/hello.txt
        '';
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8080 --bind 127.0.0.1 --directory /var/www";
      };
    };

    nodes.client = {...}: {
      imports = [(common "client")];
      services.needlecast.client = {
        enable = true;
        peer = "server";
        secretFile = "/var/lib/needlecast/secret";
      };
    };

    testScript = ''
      start_all()
      for m in (server, client):
          m.wait_for_unit("multi-user.target")

      server.wait_for_unit("devserver.service")
      server.wait_until_succeeds("ss -lnt | grep -q '127.0.0.1:8080'", timeout=30)

      server.wait_for_unit("needlecast-server.service")
      client.wait_for_unit("needlecast-client.service")
      client.wait_until_succeeds(
          "needlecast status --role client | grep -q 'state=connected'", timeout=90
      )

      # The whole point, in one line: `localhost` on the client, a server on the other machine.
      got = client.succeed("curl -sf http://localhost:8080/hello.txt").strip()
      print(f"client curled localhost:8080 and got: {got}")
      assert got == "hello from the other machine", got

      print(client.succeed("needlecast status"))
      print(server.succeed("needlecast status"))

      # The point of this suite is that you can boot it and look around, so the way in is asserted
      # rather than merely documented — otherwise it rots silently and you find out at the moment
      # you wanted it.
      for m in (server, client):
          m.wait_for_open_port(22)

      print(
          "to poke at this:  nix run .#demo  then  start_all()\\n"
          "  nix run .#demo-ssh -- client    # or `server`; key-only, no password\\n"
          "  or, in the driver:  client.shell_interact()"
      )
    '';
  }
