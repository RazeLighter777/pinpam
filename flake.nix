{
  description = "TPM-backed PIN authentication PAM module";

  inputs.nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0"; # stable Nixpkgs

  outputs =
    { self, ... }@inputs:

    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
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
      packages = forEachSupportedSystem (
        { pkgs }:
        {
          default = pkgs.stdenv.mkDerivation {
            pname = "pinpam";
            version = "0.1.0";

            src = ./.;

            nativeBuildInputs = with pkgs; [
              cmake
              pkg-config
            ];

            buildInputs = with pkgs; [
              linux-pam
              tpm2-tss
              openssl
            ];

            cmakeFlags = [
              "-DCMAKE_BUILD_TYPE=Release"
            ];

            installPhase = ''
              runHook preInstall

              # Install PAM module
              mkdir -p $out/lib/security
              cp libpinpam.so $out/lib/security/

              # Install setup_pin binary
              mkdir -p $out/bin
              cp setup_pin $out/bin/

              runHook postInstall
            '';

            meta = with pkgs.lib; {
              description = "TPM-backed PIN authentication PAM module";
              license = licenses.mit;
              platforms = platforms.linux;
              maintainers = [ ];
            };
          };
        }
      );

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.security.pinpam;
        in
        {
          options.security.pinpam = {
            enable = lib.mkEnableOption "TPM-backed PIN authentication PAM module";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.default;
              description = "The pinpam package to use";
            };

            enableTpmAccess = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Add udev rules to allow the tss group read/write access to TPM devices.
                This is required for non-root users to use the TPM for PIN operations.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            # Add the PAM module to the system
            environment.systemPackages = [ cfg.package ];

            # Set up security wrapper for setup_pin with setgid
            security.wrappers.setup_pin = {
              setgid = true;
              owner = "root";
              group = "tss";
              source = "${cfg.package}/bin/setup_pin";
            };

            # Ensure tss group exists
            users.groups.tss = {};

            # Add udev rules for TPM access by tss group
            services.udev.extraRules = lib.mkIf cfg.enableTpmAccess ''
              # TPM device access for tss group
              KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
              KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
            '';

            # Optional: Add users to tss group (uncomment and customize as needed)
            # users.users.<username>.extraGroups = [ "tss" ];
          };
        };

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
                    tpm2-tools
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
