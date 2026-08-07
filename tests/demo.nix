{
  pkgs,
  testers,
  needlecast,
  kernelPackages,
  variant,
  module,
}: let
  s = import ./lib/scenarios.nix {inherit pkgs;};

  # On disk before the unit starts and out of the store, as a real installation has it.
  placeSecret = ''
    install -Dm600 /dev/null /var/lib/needlecast/secret
    printf %s '${s.secretText}' > /var/lib/needlecast/secret
  '';

  # Shared with `nix run .#demo-ssh`, so the two cannot disagree.
  inherit (s.demoSsh) ports snakeOilPublicKey;

  common = name: {
    imports = [module];
    boot.kernelPackages = kernelPackages;
    # On, because needlecast having to ask for what it needs is part of the demonstration.
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

    # Key only: the framework gives root an empty `hashedPasswordFile` that wins over any password
    # set here, so that route cannot work.
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
  # The smallest thing that is still a real installation. Everything else in `tests/` catches a
  # specific way this could be wrong; this is just the thing working.
  #
  #     nix run .#demo
  #     >>> start_all()              # interactive mode runs only what you type
  #     >>> client.shell_interact()
  #
  # or, from another terminal:
  #
  #     nix run .#demo-ssh -- client
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

      # An ordinary dev server, bound to loopback, with no idea needlecast exists.
      systemd.services.devserver = {
        wantedBy = ["multi-user.target"];
        # Not written by the test script: in interactive mode that does not run, and the one
        # interesting file would be missing exactly when you booted this to look around.
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

      # The whole point, in one line.
      got = client.succeed("curl -sf http://localhost:8080/hello.txt").strip()
      print(f"client curled localhost:8080 and got: {got}")
      assert got == "hello from the other machine", got

      print(client.succeed("needlecast status"))
      print(server.succeed("needlecast status"))

      # Asserted rather than documented, or it rots silently.
      for m in (server, client):
          m.wait_for_open_port(22)

      print(
          "to poke at this:  nix run .#demo  then  start_all()\\n"
          "  nix run .#demo-ssh -- client    # or `server`; key-only, no password\\n"
          "  or, in the driver:  client.shell_interact()"
      )
    '';
  }
