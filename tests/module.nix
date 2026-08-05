{
  pkgs,
  testers,
  needlecast,
  kernelPackages,
  variant,
  module,
}: let
  s = import ./lib/scenarios.nix {inherit pkgs;};

  # The secret has to exist before the unit starts, and it must not be in the store — which is
  # exactly the constraint a real installation has. `LoadCredential` reads it from here.
  placeSecret = ''
    install -Dm600 /dev/null /var/lib/needlecast/secret
    printf %s '${s.secretText}' > /var/lib/needlecast/secret
  '';

  common = {
    imports = [module];
    boot.kernelPackages = kernelPackages;
    networking.firewall.enable = true; # the module is expected to open its own port
    virtualisation.vlans = [1];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    environment.systemPackages = with pkgs; [s.probe iproute2 wireguard-tools curl];
    system.activationScripts.needlecastSecret.text = placeSecret;
  };
in
  # Everything else drives the daemon with `systemd-run`, which cannot catch a module that passes a
  # flag the binary does not have. This builds both machines the way a person would install them.
  testers.runNixOSTest {
    name = "needlecast-module-${variant}";

    nodes.server = {...}: {
      imports = [common];
      services.needlecast.server = {
        enable = true;
        peer = "client";
        secretFile = "/var/lib/needlecast/secret";
        portRange = {
          from = s.portLo;
          to = s.portHi;
        };
      };
    };

    nodes.client = {...}: {
      imports = [common];
      services.needlecast.client = {
        enable = true;
        peer = "server";
        secretFile = "/var/lib/needlecast/secret";
      };
    };

    testScript = ''
      IFACE = "${s.iface}"
      SERVER_ADDR = "${s.serverAddr}"
      CLIENT_ADDR = "${s.clientAddr}"
      PORT = 8080

      def parse(out):
          d = {}
          for line in out.strip().splitlines():
              if "=" in line:
                  k, v = line.split("=", 1)
                  d[k] = v
          return d

      start_all()
      for m in (server, client):
          m.wait_for_unit("multi-user.target")

      ${s.assertKernel kernelPackages ["server" "client"]}

      with subtest("both units come up on their own"):
          server.wait_for_unit("needlecast-server.service")
          client.wait_for_unit("needlecast-client.service")
          server.wait_until_succeeds(f"ip link show {IFACE}", timeout=60)
          client.wait_until_succeeds(f"ip link show {IFACE}", timeout=60)

      with subtest("the secret is read through a credential, not from the store"):
          # The unit never names the file on its command line, so a `ps` cannot leak the path
          # a reader would have to know.
          unit = client.succeed("systemctl cat needlecast-client.service")
          print(unit)
          assert "LoadCredential=secret:" in unit, unit
          assert "CREDENTIALS_DIRECTORY" in unit, unit
          assert "/nix/store" not in client.succeed(
              "systemctl show -p ExecStart needlecast-client.service | grep -o '/var/lib[^ ]*' || true"
          )

      with subtest("a version mismatch would be stationary rather than a crash loop"):
          for m, unit in ((server, "needlecast-server"), (client, "needlecast-client")):
              out = m.succeed(f"systemctl show -p RestartPreventExitStatus {unit}.service")
              print(out.strip())
              assert "78" in out, out

      # The module uses only the ordinary `networking.firewall` options, so this is asserted by
      # behaviour rather than by grepping a ruleset — which would bind the test to one backend and
      # tell you nothing about whether traffic actually flows.
      with subtest("a port outside the managed range is not reachable over the tunnel"):
          # Bound to 0.0.0.0 so it is reachable on the tunnel address if anything lets it through,
          # and outside the range so nothing should. This is the assertion the narrow rules exist
          # for: without them, trusting the interface would quietly make this succeed.
          server.succeed(
              "systemd-run --unit=outside --collect "
              "nc-probe serve --bind 0.0.0.0 --port 9500 --token should-not-be-reachable --hold 60"
          )
          server.wait_until_succeeds("ss -lnt | grep -q '0.0.0.0:9500'", timeout=30)
          r = parse(client.succeed(
              f"nc-probe connect --host {SERVER_ADDR} --port 9500 --timeout 8 || true"
          ))
          print(f"a 0.0.0.0 service outside the range: {r}")
          assert r.get("data") != "should-not-be-reachable", r

      with subtest("the tunnel forms and forwarding works"):
          client.wait_until_succeeds(f"ping -c1 -W2 {SERVER_ADDR}", timeout=90)
          server.succeed(
              "systemd-run --unit=dev --collect "
              f"nc-probe serve --bind 127.0.0.1 --port {PORT} --token via-module --hold 120"
          )
          server.wait_until_succeeds(f"ss -lnt | grep -q '127.0.0.1:{PORT}'", timeout=30)
          client.wait_until_succeeds(
              "needlecast status --role client | grep -q 'state=connected'", timeout=90
          )
          r = parse(client.succeed(
              f"nc-probe connect --host 127.0.0.1 --port {PORT} || true"
          ))
          print(r)
          assert r.get("data") == "via-module", r
          assert r.get("peer") == f"127.0.0.1:{PORT}", r

      with subtest("the module's port range is what the client adopts"):
          cfg = parse(client.succeed("needlecast dev show-config"))
          assert cfg.get("port_lo") == "${toString s.portLo}", cfg
          assert cfg.get("port_hi") == "${toString s.portHi}", cfg

      with subtest("systemd restarts the daemon and it comes back"):
          client.succeed("systemctl kill -s SIGKILL needlecast-client.service")
          client.wait_until_succeeds(
              "needlecast status --role client | grep -q 'state=connected'", timeout=90
          )
          r = parse(client.succeed(
              f"nc-probe connect --host 127.0.0.1 --port {PORT} || true"
          ))
          assert r.get("data") == "via-module", r

      with subtest("stopping the units leaves no trace"):
          client.succeed("systemctl stop needlecast-client.service")
          client.wait_until_fails(f"ip link show {IFACE}", timeout=30)
          server.succeed("systemctl stop needlecast-server.service")
          server.wait_until_fails(f"ip link show {IFACE}", timeout=30)
          server.fail(f"test -e /proc/sys/net/ipv4/conf/{IFACE}/route_localnet")
    '';
  }
