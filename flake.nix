{
  description = "TPM-backed PIN authentication PAM module";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0"; # stable Nixpkgs
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    { self, nixpkgs, rust-overlay, ... }@inputs:

    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forEachSupportedSystem =
        f:
        nixpkgs.lib.genAttrs supportedSystems (
          system:
          f {
            pkgs = import nixpkgs { 
              inherit system; 
              overlays = [ rust-overlay.overlays.default ];
            };
          }
        );
    in
    {
      packages = forEachSupportedSystem (
        { pkgs }:
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "pinpam";
            version = "0.1.0";

            src = ./.;
            
            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs = with pkgs; [
              pkg-config
              rust-bin.stable.latest.default
              clang
              llvm
            ];

            buildInputs = with pkgs; [
              linux-pam
              tpm2-tss.dev
              openssl
              libclang.lib
            ];

            # Set environment variables for building
            OPENSSL_NO_VENDOR = 1;
            PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.linux-pam}/lib/pkgconfig:${pkgs.tpm2-tss.dev}/lib/pkgconfig";

            buildPhase = ''
              runHook preBuild
              
              # Build the workspace
              cargo build --release --workspace
              
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall

              # Install PAM module (shared library from pinpam-pam crate)
              mkdir -p $out/lib/security
              cp target/release/libpinpam.so $out/lib/security/

              # Install pinutil binary
              mkdir -p $out/bin
              cp target/release/pinutil $out/bin/

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
	    enableHyprlockPin = lib.mkOption {
	      type = lib.types.bool;
	      default = false;
	    };

            pinutilPath = lib.mkOption {
              type = lib.types.str;
              default = "${toString config.security.wrapperDir}/pinutil";
              description = ''
                Absolute path to the trusted pinutil binary. This value is embedded into the
                generated PIN policy to ensure pinpam only invokes the expected executable.
              '';
            };

            pinPolicy = {
              minLength = lib.mkOption {
                type = lib.types.ints.unsigned;
                default = 4;
                description = ''
                  Minimum PIN length enforced by the TPM policy.
                  Values below 4 are strongly discouraged because they significantly weaken the brute-force resistance of the PIN.
                '';
              };

              maxLength = lib.mkOption {
                type = lib.types.nullOr lib.types.ints.unsigned;
                default = 8;
                description = ''
                  Maximum PIN length enforced by the TPM policy.
                  Set to null to disable the upper bound.
                '';
              };

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
                The file must contain whitespace-separated key/value pairs understood by pinpam, such as:
                pin_min_length=4 pin_max_length=8 pin_lockout_max_attempts=5
              '';
            };
          };

          config = lib.mkIf cfg.enable (lib.mkMerge [
            {
              # Add the PAM module to the system
              environment.systemPackages = [ cfg.package ];

              # Set up security wrapper for pinutil with setgid
              security.wrappers.pinutil = {
                setgid = true;
                owner = "root";
                group = "tss";
                source = "${cfg.package}/bin/pinutil"
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
                  text =
                    let
                      policyLines = [
                        "pin_min_length=${toString cfg.pinPolicy.minLength}"
                      ]
                      ++ lib.optional (cfg.pinPolicy.maxLength != null)
                        "pin_max_length=${toString cfg.pinPolicy.maxLength}"
                      ++ [
                        "pin_lockout_max_attempts=${toString cfg.pinPolicy.maxAttempts}"
                        "pinutil_path=${toString cfg.pinutilPath}"
                      ];
                    in
                    lib.concatStringsSep "\n" (policyLines ++ [ "" ]);
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

            (lib.mkIf cfg.enableHyprlockPin {
              security.pam.services.hyprlock.rules.auth.pinpam = {
                control = "sufficient";
                order = config.security.pam.services.hyprlock.rules.auth.unix.order - 10;
                modulePath = "${cfg.package}/lib/security/libpinpam.so";
              };
            })
          ]);
        };


      devShells = forEachSupportedSystem (
        { pkgs }:
        {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [ 
              pkg-config 
              rust-bin.stable.latest.default
              clang
              llvm
            ];
            
            packages = with pkgs; [
              # Rust development tools
              rust-analyzer
              rustfmt
              clippy
              cargo-audit
              cargo-deny
              cargo-watch
              
              # System dependencies
              linux-pam
              tpm2-tss.dev
              openssl.dev
              tpm2-tools
              libclang.lib
              
              # C/C++ development tools
              clang-tools
              
              # Testing and debugging
              libpam-wrapper
              pamtester
              valgrind
              strace
              
              # Documentation and linting
              codespell
            ] ++ (if system == "aarch64-darwin" then [ ] else [ gdb ]);
            
            shellHook = ''
              # Set up environment for Rust development
              export RUST_SRC_PATH="${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}"
              export RUST_BACKTRACE=1
              
              # PKG-CONFIG setup for native dependencies  
              export PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.linux-pam}/lib/pkgconfig:${pkgs.tpm2-tss.dev}/lib/pkgconfig"
              export OPENSSL_NO_VENDOR=1
              
              # Clang setup for bindgen and native builds
              export LIBCLANG_PATH="${pkgs.libclang.lib}/lib"
              export BINDGEN_EXTRA_CLANG_ARGS="-I${pkgs.clang}/resource-root/include"
              
              # PAM testing environment
              export PAM_WRAPPER=1
              export PAM_WRAPPER_SERVICE_DIR=.
              export LD_PRELOAD=${pkgs.libpam-wrapper}/lib/libpam_wrapper.so
              
              echo "🦀 Rust TPM PIN PAM development environment loaded!"
              echo "📦 Available tools: cargo, rust-analyzer, clippy, rustfmt"
              echo "🔧 System deps: PAM, TPM2-TSS, OpenSSL"
              echo "🧪 Testing: libpam-wrapper, pamtester available"
            '';
          };
        }
      );
    };
}
