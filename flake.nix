{
  description = "virtual environments";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.devshell.url = "github:numtide/devshell";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.headscale.url = "github:juanfont/headscale/30ff8df93c4fbd734a2b8ace4cb9841da78177d6";

  inputs.flake-compat = {
    url = "github:edolstra/flake-compat";
    flake = false;
  };

  outputs =
    {
      self,
      flake-utils,
      devshell,
      nixpkgs,
      headscale,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (system: {
      packages =
        let
          pkgs = import nixpkgs { inherit system; };
          package = pkgs.callPackage ./nix/package.nix { };
        in
        {
          default = package;
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          e2e = import ./nix/e2e.nix {
            inherit headscale package;
            # The development pin predates testkit-peer's NixOS options.
            pkgs = headscale.inputs.nixpkgs.legacyPackages.${system};
          };
        };
      devShells.default =
        let
          pkgs = import nixpkgs {
            inherit system;

            overlays = [ devshell.overlays.default ];
          };
        in
        pkgs.devshell.mkShell { imports = [ (pkgs.devshell.importTOML ./devshell.toml) ]; };
    });
}
