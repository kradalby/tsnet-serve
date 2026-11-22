# Needs Linux with KVM. Run: nix build .#checks.x86_64-linux.e2e -L
{
  pkgs,
  headscale,
  package,
}:
let
  peer = {
    imports = [ headscale.nixosModules.testkit-peer ];
    environment.systemPackages = [
      pkgs.curl
      pkgs.jq
    ];
    virtualisation.memorySize = 512;
  };
in
pkgs.testers.runNixOSTest {
  name = "tsnet-serve-headscale";
  nodes = {
    headscale = {
      imports = [ headscale.nixosModules.testkit ];
      virtualisation.memorySize = 768;
      environment.systemPackages = [ pkgs.openssl ];
      services.headscale.settings.dns = {
        base_domain = "tailnet.test";
        certificates.enabled = true;
        # Advertise CertDomains; the cached certificate avoids public ACME/DNS.
        challenge.provider = {
          name = "rfc2136";
          server = "127.0.0.1:53";
          key_name = "fixture";
          key = "c2VjcmV0";
          key_alg = "hmac-sha256";
        };
      };
    };
    app = {
      virtualisation.memorySize = 768;
      environment.systemPackages = [
        package
        pkgs.curl
        pkgs.jq
      ];
      # tsnet's userspace netstack binds an ephemeral UDP port for direct traffic.
      networking.firewall.enable = false;
      systemd.services.tsnet-serve = {
        # Configuration cases deliberately restart the service in quick succession.
        startLimitIntervalSec = 0;
        environment = {
          TS_CONTROL_URL = "http://headscale";
          TS_NO_LOGS_NO_SUPPORT = "1";
          SSL_CERT_FILE = "/run/ca.crt";
        };
        preStart = ''
          mkdir -p /var/lib/tsnet-serve/certs
          install -m600 /run/app.crt /var/lib/tsnet-serve/certs/proxy.tailnet.test.crt
          install -m600 /run/app.key /var/lib/tsnet-serve/certs/proxy.tailnet.test.key
        '';
        serviceConfig = {
          ExecStart = "${pkgs.lib.getExe package} -hostname ignored -backend 1 -state-dir /var/lib/tsnet-serve -control-url http://invalid";
          EnvironmentFile = "/run/proxy.env";
          DynamicUser = true;
          StateDirectory = "tsnet-serve";
          StateDirectoryMode = "0700";
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          NoNewPrivileges = true;
          # Without this, tsnet binds to the default-route user-net NIC, not the VLAN.
          AmbientCapabilities = [ "CAP_NET_ADMIN" ];
          CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
          KillSignal = "SIGINT";
        };
      };
      systemd.services.backend = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.python3}/bin/python ${./backend.py}";
          DynamicUser = true;
          NoNewPrivileges = true;
        };
      };
      systemd.services.backend-tls.serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python ${./backend.py} /run/backend.crt /run/backend.key";
        DynamicUser = true;
        NoNewPrivileges = true;
      };
    };
    direct.imports = [ peer ];
    relay = {
      imports = [ peer ];
      systemd.services.tailscaled.environment.TS_DEBUG_ALWAYS_USE_DERP = "1";
    };
    denied.imports = [ peer ];
  };
  testScript = builtins.readFile ./e2e.py;
}
