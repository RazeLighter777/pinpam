{
  description = "A Nix-flake-based C/C++ development environment";

  inputs.nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0"; # stable Nixpkgs

  outputs =
    { self, ... }@inputs:

    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forEachSupportedSystem =
        f:
        inputs.nixpkgs.lib.genAttrs supportedSystems (
          system:
          f {
            pkgs = import inputs.nixpkgs { inherit system; };
          }
        );
    in
    {
      devShells = forEachSupportedSystem (
        { pkgs }:
        {
          default =
            pkgs.mkShell.override
              {
                # Override stdenv in order to change compiler:
                # stdenv = pkgs.clangStdenv;
              }
              {
                nativeBuildInputs = with pkgs; [ pkg-config ];
                packages =
                  with pkgs;
                  [
                    clang-tools
                    cmake
                    codespell
                    conan
                    cppcheck
                    doxygen
                    gtest
                    lcov
                    linux-pam
                    tpm2-tss
                    libpam-wrapper
                    pamtester
                    openssl.dev
                  ]
                  ++ (if system == "aarch64-darwin" then [ ] else [ gdb ]);
                shellHook = ''
                  export PAM_WRAPPER=1
                  export PAM_WRAPPER_SERVICE_DIR=.
                  export LD_PRELOAD=${pkgs.libpam-wrapper}/lib/libpam_wrapper.so
                '';
              };
        }
      );
    };
}
