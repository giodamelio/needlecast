{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.needlecast;

  # `EX_CONFIG`. needlecast exits with this on a version mismatch, which retrying cannot fix.
  exitVersionMismatch = 78;

  # Hardcoded in the daemon too: not a knob.
  ifaceName = "needle";

  half = role: c: let
    ports =
      lib.optionals (role == "server")
      ["--port-lo" (toString c.portRange.from) "--port-hi" (toString c.portRange.to)];
    args =
      ["${lib.getExe cfg.package}" role "\${CREDENTIALS_DIRECTORY}/secret" c.peer]
      ++ ["--listen-port" (toString c.listenPort)]
      ++ ["--control-port" (toString c.controlPort)]
      ++ ports
      ++ lib.optionals (role == "client") ["--syncnt" (toString c.syncnt)]
      ++ c.extraArgs;
  in {
    description = "needlecast ${role}";
    wantedBy = ["multi-user.target"];
    after = ["network-online.target"];
    wants = ["network-online.target"];

    serviceConfig = {
      ExecStart = lib.escapeShellArgs args;
      Restart = "always";
      RestartSec = 2;
      # A crash loop would bury the one log line that explains it.
      RestartPreventExitStatus = toString exitVersionMismatch;

      # So the secret never appears in the store or on the command line.
      LoadCredential = "secret:${c.secretFile}";

      # Interface, BPF load, cgroup attach, one sysctl. That is the whole capability set.
      AmbientCapabilities = [
        "CAP_NET_ADMIN"
        "CAP_BPF"
        "CAP_PERFMON"
        "CAP_SYS_ADMIN"
      ];
      CapabilityBoundingSet = [
        "CAP_NET_ADMIN"
        "CAP_BPF"
        "CAP_PERFMON"
        "CAP_SYS_ADMIN"
      ];

      RuntimeDirectory = "needlecast";
      ProtectHome = true;
      ProtectHostname = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = false; # it attaches to the cgroup tree
      RestrictAddressFamilies = ["AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK"];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = false; # the BPF loader maps writable pages
      SystemCallArchitectures = "native";
    };
  };

  halfOptions = role:
    {
      enable = lib.mkEnableOption "the needlecast ${role}";

      peer = lib.mkOption {
        type = lib.types.str;
        example = "cadmium.gio.ninja";
        description = ''
          The *other* machine's DNS name. Re-resolved while running, so a peer that moves is
          followed rather than silently unreachable.
        '';
      };

      secretFile = lib.mkOption {
        type = lib.types.path;
        example = "/var/lib/needlecast/secret";
        description = ''
          The shared secret, identical on both machines: each side derives both keypairs from it,
          so there is nothing to exchange.

          Generate it with `head -c 32 /dev/urandom | base64 > secret`. Anyone holding it can
          impersonate either side, so keep it out of the store — a lost laptop is a
          rotate-the-secret event.
        '';
      };

      listenPort = lib.mkOption {
        type = lib.types.port;
        default = 47654;
        description = "WireGuard port. Must match on both machines.";
      };

      controlPort = lib.mkOption {
        type = lib.types.port;
        default = 47653;
        description = "Control port, inside the tunnel. Must match on both machines.";
      };

      extraArgs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Extra arguments appended to the command line.";
      };

      openFirewall = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Open the ports needlecast needs, using ordinary `networking.firewall` options: the
          WireGuard port on both halves, plus the managed range and the control port on the
          server's tunnel interface.

          Deliberately *not* `trustedInterfaces`, which would also expose every service bound to
          `0.0.0.0` outside the managed range.

          Elsewhere the equivalent is: allow inbound UDP on the WireGuard port, and on `needle`
          allow inbound TCP and UDP for the managed range plus TCP on the control port.
        '';
      };
    }
    // lib.optionalAttrs (role == "server") {
      portRange = lib.mkOption {
        type = lib.types.submodule {
          options = {
            from = lib.mkOption {
              type = lib.types.port;
              default = 8000;
            };
            to = lib.mkOption {
              type = lib.types.port;
              default = 8999;
            };
          };
        };
        default = {};
        description = ''
          The loopback ports this machine serves to the client. Every one of them is reachable to
          anyone holding the secret, and this range is the only limit — there is no per-port
          allowlist — so keep anything you do not want reachable outside it.
        '';
      };
    }
    // lib.optionalAttrs (role == "client") {
      syncnt = lib.mkOption {
        type = lib.types.ints.between 0 255;
        default = 2;
        description = ''
          `TCP_SYNCNT` for rewritten sockets: a few seconds instead of the stock two minutes when
          the server vanishes between heartbeats. Zero leaves the system default.
        '';
      };
    };
in {
  options.services.needlecast = {
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.needlecast or (throw "set services.needlecast.package, or use this flake's nixosModules.default");
      defaultText = lib.literalExpression "pkgs.needlecast";
      description = "The needlecast package to run.";
    };
    server = halfOptions "server";
    client = halfOptions "client";
  };

  config = lib.mkIf (cfg.server.enable || cfg.client.enable) {
    assertions = [
      {
        assertion = !(cfg.server.enable && cfg.client.enable);
        message = ''
          services.needlecast.server and .client cannot both run on one machine: they would fight
          over the same `needle` interface and the same addresses.
        '';
      }
    ];

    environment.systemPackages = [cfg.package];

    systemd.services =
      lib.optionalAttrs cfg.server.enable {needlecast-server = half "server" cfg.server;}
      // lib.optionalAttrs cfg.client.enable {needlecast-client = half "client" cfg.client;};

    networking.firewall = let
      # Both halves listen, so whichever is reachable first can start the handshake.
      wgPorts =
        lib.optionals (cfg.server.enable && cfg.server.openFirewall) [cfg.server.listenPort]
        ++ lib.optionals (cfg.client.enable && cfg.client.openFirewall) [cfg.client.listenPort];

      range = {
        from = cfg.server.portRange.from;
        to = cfg.server.portRange.to;
      };
    in
      {
        allowedUDPPorts = wgPorts;
      }
      // lib.optionalAttrs (cfg.server.enable && cfg.server.openFirewall) {
        # Ports are never translated, so a forwarded packet's destination port is the one the
        # client asked for — which makes the managed range exactly the right filter, and keeps it
        # the only limit on what the secret grants.
        interfaces.${ifaceName} = {
          allowedTCPPorts = [cfg.server.controlPort];
          allowedTCPPortRanges = [range];
          allowedUDPPortRanges = [range];
        };
      };
  };
}
