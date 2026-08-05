{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.needlecast;

  # `EX_CONFIG` from sysexits. needlecast exits with this on a protocol version mismatch, which is
  # fatal by design — so the unit must let the failure be loud and *stationary* rather than turning
  # it into a crash loop.
  exitVersionMismatch = 78;

  # The interface needlecast creates. Hardcoded in the daemon too — it is not a knob.
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
      # A version mismatch means the two machines disagree about the protocol. Retrying cannot fix
      # that, and a crash loop would bury the one log line that explains it.
      RestartPreventExitStatus = toString exitVersionMismatch;

      # The secret never appears in the store or in a world-readable path.
      LoadCredential = "secret:${c.secretFile}";

      # needlecast creates a WireGuard interface, loads BPF programs, attaches them to the root
      # cgroup, and writes one sysctl on its own interface. That is the whole capability set.
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
          Path to the shared secret. The same file must be on both machines: each side derives
          both keypairs from it, so there is nothing to exchange.

          Generate it once with `head -c 32 /dev/urandom | base64 > secret`. Anyone holding it can
          impersonate either side, so keep it out of the store and off shared filesystems — a lost
          laptop is a rotate-the-secret event.
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
          Open the ports needlecast needs, using the ordinary `networking.firewall` options — no
          hand-written `iptables` or `nftables` rules, and nothing that depends on which backend
          you run.

          The WireGuard port, on both halves, so whichever machine is reachable first can start the
          handshake. On the server, additionally the managed port range and the control port, scoped
          to the tunnel interface.

          Deliberately *not* `trustedInterfaces`, which would also expose every service bound to
          `0.0.0.0` on ports outside the managed range and break the guarantee that the range is the
          only limit.

          On a machine that is not NixOS, the equivalent is: allow inbound UDP on the WireGuard
          port, and on the `needle` interface allow inbound TCP and UDP for the managed range plus
          TCP on the control port.
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
          The loopback ports this machine serves to the client.

          Every port in the range becomes reachable to anyone holding the secret. This range is the
          only limit — there is no per-port allowlist — so keep anything you do not want reachable
          outside it.
        '';
      };
    }
    // lib.optionalAttrs (role == "client") {
      syncnt = lib.mkOption {
        type = lib.types.ints.between 0 255;
        default = 2;
        description = ''
          `TCP_SYNCNT` for rewritten sockets. Caps how long a connection hangs when the server
          vanishes between heartbeats: a few seconds instead of the stock two minutes. Zero leaves
          the system default.
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
      # Both halves listen for WireGuard, so whichever machine is reachable first can be the one
      # that initiates the handshake.
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
        # Scoped to the tunnel interface, and to the ports needlecast actually forwards. Ports are
        # never translated, so the destination port of a forwarded packet is the one the client
        # asked for — which means the managed range is exactly the right filter and the range stays
        # the only limit on what the secret grants.
        interfaces.${ifaceName} = {
          allowedTCPPorts = [cfg.server.controlPort];
          allowedTCPPortRanges = [range];
          allowedUDPPortRanges = [range];
        };
      };
  };
}
