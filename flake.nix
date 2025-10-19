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

            enableSudoPin = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Enable TPM PIN authentication for sudo.
                This adds the pinpam module to sudo's PAM configuration with priority 10 lower
                than standard unix authentication (order = config.security.pam.services.sudo.rules.auth.unix.order + 10).
                Users can authenticate with either their standard password or TPM PIN.
              '';
            };

            pinPolicy = {
              maxAttempts = lib.mkOption {
                type = lib.types.ints.unsigned;
                default = 5;
                description = ''
                  Maximum number of failed PIN attempts before user lockout.
                  Set to 0 to disable lockout entirely.
                  This configures per-user PIN counters using TPM_NT_PIN_FAIL hardware-backed protection.
                '';
              };
            };

            policyFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = ''
                Path to a custom PIN counter policy configuration file.
                If set, this file will be used instead of the auto-generated one from pinPolicy options.
                The file should contain: max_attempts=N
              '';
            };
          };

          config = lib.mkIf cfg.enable (lib.mkMerge [
            {
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

              # Install policy file
              environment.etc."pinpam/policy" = 
                if cfg.policyFile != null then {
                  # Use custom policy file
                  source = cfg.policyFile;
                  mode = "0644";
                  user = "root";
                  group = "root";
                } else {
                  # Generate policy file from pinPolicy options
                  text = ''
                    # TPM PIN Counter Policy Configuration
                    # Auto-generated from NixOS configuration
                    max_attempts=${toString cfg.pinPolicy.maxAttempts}
                  '';
                  mode = "0644";
                  user = "root";
                  group = "root";
                };
            }

            # TPM access configuration
            (lib.mkIf cfg.enableTpmAccess {
              # Enable udev service
              services.udev.enable = true;

              # Add udev rules for TPM access by tss group
              services.udev.extraRules = ''
                # TPM device access for tss group
                KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
                KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
              '';
            })

            # Sudo PAM configuration
            (lib.mkIf cfg.enableSudoPin {
              security.pam.services.sudo.rules.auth.pinpam = {
                control = "sufficient";
                modulePath = "${cfg.package}/lib/security/libpinpam.so";
                order = config.security.pam.services.sudo.rules.auth.unix.order - 10;
              };
            })
          ]);
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
