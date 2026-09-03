{pkgs}: let
  # Test-only keys. Committing them is deliberate: they exist so the two nodes can agree without a
  # key-exchange step, and the whole network lives inside one VM test.
  keys = {
    laptopPrivate = "eP9WzfvDK1vfQtihbrozcwAj3uoIMVG1P14pDJf95nE=";
    laptopPublic = "LJ3w0f6XnaSbYYPVLqyWvh6H1ElVSumBiWRkKbNP+jE=";
    desktopPrivate = "mEe2BNeQNCkE70QjQW1F8F8WqTR3Rex4bRo0u/elIm4=";
    desktopPublic = "z02UTnTLDfCOEtllwCnlf4ysdC6meNy7D7D6CxqsAwo=";
  };

  keyFile = name: value: pkgs.writeText "wg-${name}" value;

  # Both transports present the same addresses on the same interface name from the test's point of
  # view, so every Phase 3 assertion runs unchanged against WireGuard in Phase 4. The differences
  # that matter — link-layer header, MTU, allowed-ips — are exactly what Phase 4 is testing.
  # A ULA of the same shape the daemon derives, fixed here because the harness is driven by flags
  # rather than by a secret.
  laptopV6 = "fd7c:a5e0:1::1";
  desktopV6 = "fd7c:a5e0:1::2";

  ethernet = {
    iface = "eth1";
    laptopAddr = "10.7.0.1";
    desktopAddr = "10.7.0.2";
    laptopAddr6 = laptopV6;
    desktopAddr6 = desktopV6;
    mtu = 1500;
    laptop = {
      networking.interfaces.eth1.ipv4.addresses = [
        {
          address = "10.7.0.1";
          prefixLength = 24;
        }
      ];
      networking.interfaces.eth1.ipv6.addresses = [
        {
          address = laptopV6;
          prefixLength = 48;
        }
      ];
    };
    desktop = {
      networking.interfaces.eth1.ipv4.addresses = [
        {
          address = "10.7.0.2";
          prefixLength = 24;
        }
      ];
      networking.interfaces.eth1.ipv6.addresses = [
        {
          address = desktopV6;
          prefixLength = 48;
        }
      ];
    };
  };

  wireguard = {
    iface = "wg0";
    laptopAddr = "10.7.0.1";
    desktopAddr = "10.7.0.2";
    laptopAddr6 = laptopV6;
    desktopAddr6 = desktopV6;
    mtu = 1420;
    laptop = {
      networking.wireguard.interfaces.wg0 = {
        ips = ["10.7.0.1/24" "${laptopV6}/48"];
        listenPort = 51820;
        privateKeyFile = "${keyFile "laptop" keys.laptopPrivate}";
        peers = [
          {
            publicKey = keys.desktopPublic;
            allowedIPs = ["10.7.0.0/24" "fd7c:a5e0:1::/48"];
            # By name, not by address: the test framework assigns vlan addresses in an order that
            # is not obvious, and /etc/hosts in a NixOS test maps every machine name to its
            # vlan address.
            endpoint = "desktop:51820";
            persistentKeepalive = 5;
          }
        ];
      };
    };
    desktop = {
      networking.wireguard.interfaces.wg0 = {
        ips = ["10.7.0.2/24" "${desktopV6}/48"];
        listenPort = 51820;
        privateKeyFile = "${keyFile "desktop" keys.desktopPrivate}";
        peers = [
          {
            publicKey = keys.laptopPublic;
            allowedIPs = ["10.7.0.0/24" "fd7c:a5e0:1::/48"];
            endpoint = "laptop:51820";
            persistentKeepalive = 5;
          }
        ];
      };
    };
  };
in {inherit ethernet wireguard;}
