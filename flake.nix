{
  description = "QEMU development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              config.allowUnfree = true;
            }
          )
        );
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          name = "qemu-dev";

          packages = with pkgs; [
            # Build system
            meson
            ninja
            pkg-config

            # Compiler/tooling
            gcc
            clang
            clang-tools
            gdb
            lldb

            # QEMU dependencies
            glib
            pixman
            zlib
            libslirp
            libusb1
            libepoxy

            # Build helpers
            python3
            python3Packages.sphinx
            python3Packages.pip

            # Utilities
            git
            ccache
            ripgrep
            bear
          ];

          nativeBuildInputs = with pkgs; [
            perl
            gettext
          ];

          hardeningDisable = [ "all" ];
          NIX_HARDENING_ENABLE = "";

          shellHook = ''
            export CC=clang
            export CXX=clang++

            echo "QEMU dev shell"
            echo "Configure with:"
            echo "  ./configure --target-list=x86_64-softmmu --enable-debug"
          '';
        };
      });
    };
}
