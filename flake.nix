{
  description = "TPM-backed PIN authentication PAM module";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0"; # stable Nixpkgs
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      ...
    }@inputs:

    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      mkPinpamPackage =
        pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "pinpam";
          version = "0.1.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = with pkgs; [
            pkg-config
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
            cp target/release/libpinpam_master_key.so $out/lib/security/

            # Install pinutil binary
            mkdir -p $out/bin
            cp target/release/pinutil $out/bin/

            runHook postInstall
          '';
          phases = [
            "unpackPhase"
            "buildPhase"
            "installPhase"
          ];

          meta = with pkgs.lib; {
            description = "TPM-backed PIN authentication PAM module";
            license = licenses.mit;
            platforms = platforms.linux;
            maintainers = [ ];
          };
        };
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
          default = mkPinpamPackage pkgs;
        }
      );

      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.security.pinpam;

          mkPinpamAuthRule = _service:
            {
              rules.auth.pinpam = {
                control = cfg.auth.control;
                modulePath = "${cfg.package}/lib/security/libpinpam.so";
                order = cfg.auth.fallbackOrder;
              };
            };

          # Name of the generated auth-decision substack for a service.
          masterKeySubstackName = service: "pinpam-decide-${service}";

          # Auth rules already configured for a service by other NixOS modules.
          # Only ever read for VALUES (modulePath/args/order) inside lazily
          # evaluated fields; never used to decide which keys this module
          # contributes to `rules.auth`, since reading the keyset of an attrset
          # we also write to is an infinite recursion.
          authRulesFor = service:
            lib.attrByPath [ service "rules" "auth" ] { } config.security.pam.services;

          # Curated success-method names actually present in the service, sorted
          # in their existing stack order so PIN is tried before the password.
          # `rules ? name` here is safe: it runs while evaluating the substack
          # file text, after the (statically keyed) rule set is computable.
          presentSuccessRules = service: serviceCfg:
            let
              rules = authRulesFor service;
              present = lib.filter (name: rules ? ${name}) (lib.unique serviceCfg.successRules);
            in
            lib.sort (a: b: rules.${a}.order < rules.${b}.order) present;

          # Escape a module argument the same way nixpkgs' pam renderer does.
          formatPamArg = token:
            if lib.hasInfix " " token then
              "[${lib.replaceStrings [ "]" ] [ "\\]" ] token}]"
            else
              token;

          # Render the decision substack file. Each curated success method
          # becomes a `sufficient` line: its short-circuit ("done") is confined
          # to the substack, so the parent stack still runs the master-key +
          # keyring stages afterwards. A terminal `requisite pam_deny` makes the
          # substack fail iff no method authenticated.
          mkMasterKeySubstackText = service: serviceCfg:
            let
              rules = authRulesFor service;
              lines = map (
                name:
                let r = rules.${name}; in
                lib.concatStringsSep " " (
                  [ "auth" "sufficient" r.modulePath ] ++ map formatPamArg r.args
                )
              ) (presentSuccessRules service serviceCfg);
            in
            ''
              # Generated by pinpam. PIN-or-fallback auth decision for "${service}".
              # Each method is `sufficient`; its short-circuit stays confined to
              # this substack so the parent stack runs the master-key + keyring
              # stages on success. The trailing deny fails the substack (and thus
              # the parent) only when every method above failed.
              ${lib.concatStringsSep "\n" lines}
              auth requisite pam_deny.so
            '';

          mkMasterKeyService = service: serviceCfg:
            let
              # Anchor everything to the service's terminal deny rule (always
              # present). Read of `.order` is a value read and does not depend on
              # this module's key contributions, so it cannot recurse.
              denyAnchorOrder =
                lib.attrByPath [ serviceCfg.denyAnchorRule "order" ]
                  cfg.masterKey.fallbackDenyOrder
                  (authRulesFor service);
              decideOrder = denyAnchorOrder - 40;
              masterKeyOrder = denyAnchorOrder - 30;

              # All override keysets below are STATIC (derived from the option
              # lists, not from the live rule set), so the merged `rules.auth`
              # key set stays computable without forcing these values.

              # The curated success methods now live in the substack; disable the
              # inline copies so they are not also evaluated in the parent. A name
              # that does not exist becomes a harmless disabled stub (filtered out
              # before its required fields are read).
              disableSuccessOverrides =
                lib.genAttrs (lib.unique serviceCfg.successRules)
                  (_: { enable = lib.mkForce false; });

              # A substack cannot short-circuit its parent, so the parent's
              # terminal `required pam_deny` would fail even a successful login.
              # The substack's own deny is the all-failed backstop instead.
              disableDenyOverride = {
                ${serviceCfg.denyAnchorRule}.enable = lib.mkForce false;
              };

              # Move keyring rules to run right after the master-key stage so they
              # capture the freshly-stamped AUTHTOK. Keys are static, so a name
              # that is absent from the service still gets a definition here. The
              # `mkDefault` filler turns such an absent name into a disabled stub
              # (filtered out before rendering); a real keyring rule sets these
              # fields at normal priority and wins, keeping its module path while
              # adopting the forced order.
              postRuleOrderOverrides =
                lib.listToAttrs (
                  lib.imap0 (
                    index: name:
                    lib.nameValuePair name {
                      order = lib.mkForce (masterKeyOrder + 1 + index);
                      enable = lib.mkOverride 1490 false;
                      control = lib.mkDefault "optional";
                      modulePath = lib.mkDefault "pam_deny.so";
                    }
                  ) (lib.unique serviceCfg.postAuthRules)
                );

              composedOverrides =
                lib.foldl' lib.recursiveUpdate { } [
                  disableSuccessOverrides
                  disableDenyOverride
                  postRuleOrderOverrides
                ];
            in
            {
              rules.auth = composedOverrides // {
                # The decision substack. On failure its internal deny fails the
                # substack; the parent then ends without a success, denying auth.
                pinpamMasterKeyDecide = {
                  control = "substack";
                  modulePath = masterKeySubstackName service;
                  order = decideOrder;
                };

                # Stamp AUTHTOK with the per-user wallet token. Side-effect only:
                # the module returns PAM_IGNORE and never affects the decision.
                pinpamMasterKey = {
                  control = cfg.masterKey.control;
                  modulePath = "${cfg.package}/lib/security/libpinpam_master_key.so";
                  order = masterKeyOrder;
                };
              };
            };

          enabledAuthServices = lib.unique cfg.auth.services;
          enabledMasterKeyServices = lib.filterAttrs (_: serviceCfg: serviceCfg.enable) cfg.masterKey.services;

          moduleEnabled = cfg.enable || cfg.auth.enable || cfg.masterKey.enable;
        in
        {
          options.security.pinpam = {
            enable = lib.mkEnableOption "pinpam integration base settings";

            package = lib.mkOption {
              type = lib.types.package;
              default = mkPinpamPackage pkgs;
              description = "The pinpam package to use";
            };

            tpm = {
              enableAccess = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = "Configure TPM device access for the pinpam runtime group.";
              };

              group = lib.mkOption {
                type = lib.types.str;
                default = "tss";
                description = "Group granted access to TPM character devices.";
              };
            };

            pin = {
              pinutilPath = lib.mkOption {
                type = lib.types.str;
                default = "/run/wrappers/bin/pinutil";
                defaultText = lib.literalExpression ''"\${config.security.wrapperDir}/pinutil"'';
                description = ''
                  Absolute path to trusted pinutil used in generated PIN policy.
                '';
              };

              policyFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Optional path to a custom pinpam policy file.";
              };

              policy = {
                minLength = lib.mkOption {
                  type = lib.types.ints.unsigned;
                  default = 4;
                  description = "Minimum PIN length.";
                };

                maxLength = lib.mkOption {
                  type = lib.types.nullOr lib.types.ints.unsigned;
                  default = 8;
                  description = "Maximum PIN length (null disables upper bound).";
                };

                maxAttempts = lib.mkOption {
                  type = lib.types.ints.unsigned;
                  default = 5;
                  description = "Maximum failed PIN attempts before lockout.";
                };

                allowAlphanumeric = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = ''
                    Allow PINs to contain any printable ASCII character
                    (0x20-0x7E), e.g. letters and symbols, instead of only
                    decimal digits. Stricter composition rules belong in other
                    PAM modules stacked alongside pinpam.
                  '';
                };
              };
            };

            auth = {
              enable = lib.mkEnableOption "pinpam PIN authentication PAM module";

              services = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                description = ''
                  PAM services to receive the pinpam auth module.
                  Examples: [ "sudo" "login" "hyprlock" "polkit-1" "kde" "system-auth" ].
                '';
              };

              control = lib.mkOption {
                type = lib.types.str;
                default = "sufficient";
                description = "PAM control value used for the pinpam auth module.";
              };

              fallbackOrder = lib.mkOption {
                type = lib.types.int;
                default = 11050;
                description = "Fallback auth rule order when no unix anchor rule exists.";
              };

              preferOrderBeforeUnix = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = "Place pinpam before unix when the unix rule exists.";
              };

              orderOffsetFromUnix = lib.mkOption {
                type = lib.types.int;
                default = 50;
                description = "Offset subtracted from unix order when preferOrderBeforeUnix is true.";
              };
            };

            masterKey = {
              enable = lib.mkEnableOption "pinpam master-key AUTHTOK PAM module";

              control = lib.mkOption {
                type = lib.types.str;
                default = "optional";
                description = "PAM control value for the master-key module itself.";
              };

              fallbackDenyOrder = lib.mkOption {
                type = lib.types.int;
                default = 13700;
                description = "Fallback deny anchor order when the service deny rule is absent.";
              };

              services = lib.mkOption {
                type = lib.types.attrsOf (
                  lib.types.submodule {
                    options = {
                      enable = lib.mkEnableOption "master-key flow for this service";

                      denyAnchorRule = lib.mkOption {
                        type = lib.types.str;
                        default = "deny";
                        description = "Existing rule used as the ordering anchor for injected master-key rules.";
                      };

                      successRules = lib.mkOption {
                        type = lib.types.listOf lib.types.str;
                        default = [
                          "pinpam"
                          "unix"
                        ];
                        description = ''
                          Auth rule names whose success should route into the master-key
                          stage. Each listed rule is copied into the generated decision
                          substack as a `sufficient` method and disabled in the parent
                          stack, so its short-circuit no longer skips the master-key and
                          keyring stages.

                          List exactly the `sufficient` methods you actually use. Add your
                          network/identity methods here too (e.g. `systemd_home`, `ldap`,
                          `kanidm`, `sss`). Note: these rules always exist in the NixOS
                          rule set even when their feature is disabled, and the module
                          cannot read a rule's original `enable` while overriding it, so a
                          name listed here is always copied into the substack regardless of
                          whether its backing feature is on.
                        '';
                      };

                      postAuthRules = lib.mkOption {
                        type = lib.types.listOf lib.types.str;
                        default = [
                          "kwallet"
                          "gnupg"
                          "gnome_keyring"
                          "intune"
                          "mount"
                          "zfs_key"
                          "fscrypt"
                        ];
                        description = ''
                          Existing auth rules moved to execute after master-key so they can
                          consume updated AUTHTOK.
                        '';
                      };
                    };
                  }
                );
                default = { };
                description = ''
                  Per-service master-key configuration.
                  Keys are PAM service names (e.g. hyprlock, sudo, polkit-1).
                '';
              };
            };

            polkit = {
              enableAgentTpmAccess = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = ''
                  Allow TPM access inside polkit-agent-helper sandbox when polkit-1 is targeted.
                '';
              };
            };

            pinutil = {
              enableWrapper = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = "Install setgid pinutil wrapper for TPM group access.";
              };
            };
          };

          config = lib.mkIf moduleEnabled (
            lib.mkMerge [
              {
                environment.systemPackages = [ cfg.package ];
              }

              (lib.mkIf cfg.pinutil.enableWrapper {
                security.wrappers.pinutil = {
                  setgid = true;
                  owner = "root";
                  group = cfg.tpm.group;
                  source = "${cfg.package}/bin/pinutil";
                };
              })

              (lib.mkIf cfg.tpm.enableAccess {
                users.groups.${cfg.tpm.group} = { };
                services.udev.enable = true;
                services.udev.extraRules = ''
                  KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", GROUP="${cfg.tpm.group}"
                  KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="${cfg.tpm.group}"
                '';
              })

              (lib.mkIf cfg.auth.enable {
                security.pam.services = lib.listToAttrs (
                  map (
                    service:
                    lib.nameValuePair service (mkPinpamAuthRule service)
                  ) enabledAuthServices
                );

                environment.etc."pinpam/policy" =
                  if cfg.pin.policyFile != null then
                    {
                      source = cfg.pin.policyFile;
                      mode = "0644";
                      user = "root";
                      group = "root";
                    }
                  else
                    {
                      text =
                        let
                          lines = [
                            "pin_min_length=${toString cfg.pin.policy.minLength}"
                          ]
                          ++ lib.optional (cfg.pin.policy.maxLength != null)
                            "pin_max_length=${toString cfg.pin.policy.maxLength}"
                          ++ [
                            "pin_lockout_max_attempts=${toString cfg.pin.policy.maxAttempts}"
                            "allow_alphanumeric_pins=${lib.boolToString cfg.pin.policy.allowAlphanumeric}"
                            "pinutil_path=${cfg.pin.pinutilPath}"
                          ];
                        in
                        lib.concatStringsSep "\n" (lines ++ [ "" ]);
                      mode = "0644";
                      user = "root";
                      group = "root";
                    };
              })

              (lib.mkIf cfg.masterKey.enable {
                security.pam.services = lib.mapAttrs mkMasterKeyService enabledMasterKeyServices;

                # Write each generated auth-decision substack to /etc/pam.d so the
                # `auth substack pinpam-decide-<service>` references resolve.
                environment.etc = lib.mapAttrs' (
                  service: serviceCfg:
                  lib.nameValuePair "pam.d/${masterKeySubstackName service}" {
                    text = mkMasterKeySubstackText service serviceCfg;
                  }
                ) enabledMasterKeyServices;
              })

              (lib.mkIf (
                cfg.polkit.enableAgentTpmAccess
                && (
                  (cfg.auth.enable && lib.elem "polkit-1" enabledAuthServices)
                  || lib.hasAttr "polkit-1" enabledMasterKeyServices
                )
              ) {
                systemd.services."polkit-agent-helper@".serviceConfig = {
                  PrivateDevices = "no";
                  DeviceAllow = [
                    "/dev/tpmrm0 rw"
                    "/dev/ptmx rw"
                  ];
                };
              })
            ]
          );
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

            packages =
              with pkgs;
              [
                # Rust development tools
                rust-analyzer
                cargo-audit
                cargo-deny
                cargo-watch

                # System dependencies
                linux-pam
                tpm2-tss.dev
                openssl.dev
                tpm2-tools
                swtpm
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
              ]
              ++ (if system == "aarch64-darwin" then [ ] else [ gdb ]);

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
