# pinpam

pinpam is a PAM module and credential utility to enable system-wide authentication with a secure TPM2-backed pin.

# Updates
- v0.0.5 :
  - Experimental support for master-key, seperate optional feature allowing keyring integration and automatic unlocking
    regardless of auth method! This is a seprate pam module and subproject, and is entirely optional
  - Large refactoring, reduction in unsafe code surface (it's still needed for TPM methods using unsafe C FFI and PAM using unsafe C FFI)
  - Fix minor uid overflow bug that could result in errors.
  - Add AI generated slovak translations to existing human ones. (improvements welcome)
  - Add automatic sandboxing override for arch linux pkgbuild
  - swtpm based integration testing.
  - Fix minor security issue where RUST_LOG would allow enumeration of tpm general details (not key data) by unprivileged user.
  - Improve comments and update documentation.
  - Updates to nix flake format.
  - Note: though the diff is large, most additions were to the test suite and the new pam master-key module.
- v0.0.4 :
  - skiselkov (6): Add machine readable output/input, and Slovak language support, localization, and various cleanups.
  - RazeLighter777 (3): Fix leading zero pin truncation (with migration for old format), update README.md, remove PTY usage from PAM module, bump versions, add version field to avoid future migration issues.
- v0.0.3 : fix policy access right TOCTOU (credit to nbdd0121), add landlock sandboxing, disallow ./policy as policy source.
# Features

- Hardware-backed brute force protection
- Configurable number of allowed authentication failures.
- PIN resets
- NixOS flake with pam and udev configuration options.
- AUR (Arch User Repository) package.

# FAQ

- What does this program do? : pinpam lets you use a pin to authenticate yourself on linux. This could be for logging in, sudo, or any other service supported by PAM (pluggable authentication modules).
- How is this different than setting my password to a number (and using faillock)? : pinpam stores your pin in the TPM rather than in /etc/shadow. Storing a pin in /etc/shadow is a bad idea, if that file gets leaked, depending on the length of the pin, it can be trivial to brute force and reuse those credentials on another system. pinpam protects against hash dumping attacks and credential reuse.
- How do I reset/change a pin? : User's can change their own pins if they haven't been locked out with the pinutil command. A locked out pin must be manually reset by root.
- Isn't a pin less secure than a password? : It depends. Generally a pin is less secure than a strong password, but they can be more convenient and easier for users to embrace. You should consider your threat model when implementing any authentication service.
- Can I set a lockout duration? : You cannot at this time. I wanted this feature, but TPM2 afaik doesn't support this with pinfail indexes. Global dictionary attack does, but this would get rid of per user lockouts. If you have ideas on how this can be implemented please open up an issue.
- Will changing the lockout policy file affect existing pins? : No, users must change their pins to reload a new lockout policy. Admins can accomplish this by deleting all user pins.
- Can you support OTP? : I'd like to and this is a subject of research for me. Pull requests are welcome.
- License? : This project is licensed under the GPLv3.
- Packaging? : Currently this project is only in a nixOS flake and an AUR (arch user repository) package. You can manually build it and install the binaries if you wish, it should be broadly compatible. Pull requests welcome.

# Known Workarounds

- Polkit support? : Polkit support should work OOTB for NixOS with the `enablePolkitPin` option. Currently on other distributions, polkit sandboxing break may break access to the tpm device and requires manual intervention. For a configuration fix see: [this comment](https://github.com/RazeLighter777/pinpam/issues/4#issuecomment-3815461955).

# Details

pinpam consists of two components:

1. A PAM module (`libpinpam.so`) exposing authentication functionality to PAM-aware applications.
2. A command-line utility (`pinutil`) to setup/reset/change/manage PINs.

The PINs are stored in the TPM's NVRAM, protected by the TPM's hardware-backed security features.
Upon creation, the PIN reset/attempts counter is marked read-only, preventing resetting the brute-force protection without clearing the TPM.
This makes it difficult for an attacker to brute-force the PIN, as the TPM will lock out further attempts after a configurable number of failures.
Even root will be unable to bypass this protection without clearing the TPM, which would also delete the stored PIN.

This module uses the little-known PinFail index data structure in the TPM 2.0 specification to track failed authentication attempts.
This data structure is a simple counter/max-failures pair that is incremented by the TPM on each failed authentication attempt.
When the maximum number of failures is reached, the TPM will refuse further authentication attempts until the counter is reset.

However, an attacker with root access could enumerate users pins and recover them by rewriting the PinFail index to reset the failure counter while making repeated authentication attempts.
To mitigate this, pinpam uses a TPM2 policy to restrict the PinFail index to only being written once.

See SECURITY.md for a summary of the pinpam threat model

# Important Considerations

- ⚠️⚠️⚠️ Ensure that no user on the system other than root has direct access to the TPM device (e.g., /dev/tpm0 or /dev/tpmrm0). Direct access would allow users to delete/reset other users' pins, bypassing pinpam's security features.
- A TPM2 (Trusted Platform Module) is required.
- No not give user's access to the tpm device, or they could delete/reset (but not read or brute force) other user's pins
- Losing access to the TPM (or clearing it) will result in the loss of the stored PIN and any associated data.
- You cannot reset a lockout without clearing the pin. This is a security feature to prevent brute-force attacks.
- ⚠️ Ensure you know what you are doing before marking pinpam as `required` in PAM configurations. Lockout could prevent legitimate access to the system and opens a risk of denial of service attacks. `sufficient` with a fallback method (e.g., regular unix auth) is recommended for most use cases.
- pinutil is designed to operate as a setgid/setuid binary. If setgid is used, should be set to a group with rw access to /dev/tpmrm0 (e.g., `tpm` or `tss`), assuming udev rules are set up correctly. See the NixOS flake for an example, which does this automatically, or the manual installation instructions.
- A bug was fixed in 0.0.4 which incorrectly truncated leading zeros from pins. An automatic migration was put in place for this case, but note that if you use a new version of pinutil, your PIN will no longer work with the old version and will require either resetting or using the new tool.

# pinutil usage

```
TPM PIN authentication utility

Usage: pinutil [OPTIONS] <COMMAND>

Commands:
  setup   Set up a new PIN (root or user for self)
  change  Change PIN (requires current PIN, or root)
  delete  Delete PIN (requires PIN auth for non-root, root can delete any)
  test    Test PIN authentication
  status  Show PIN status
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose
  -m, --machine  Forces machine-readable output in JSON format and disables displaying input prompts. If not provided, machine mode is automatically enabled if stdin is NOT a terminal
  -h, --help     Print help
  -V, --version  Print version
```

# Configuration syntax

Configuration file must be named policy. pinpam checks /etc/pinpam/policy. For security, it MUST be owned by root and have permissions 0644 or less
Example policy file:

```
# Lines beginning with '#' are comments, as is any text following a '#'.
pin_min_length=4
pin_max_length=6
pin_lockout_max_attempts=5
pinutil_path=/nix/store/p2799cpnhk2malpmp7ilqvxg76gajlh9-pinpam-0.1.0/bin/pinutil
tcti=device:/dev/tpmrm0 # optional TPM backend
```

Where
pin_min_length = minimum length of pin
pin_max_length = maximum length of pin
pin_lockout_max_attempts = number of allowed failed attempts before lockout
pinutil_path = path to pinutil binary to prevent path overwrite attacks. (mandatory)
tcti = optional TCTI spec naming the TPM backend (defaults to `device:/dev/tpmrm0`). Any string accepted by `tss-esapi`'s `TctiNameConf::from_str` works, e.g. `device:/dev/tpm0`, `tabrmd:bus_name=com.intel.tss2.Tabrmd`, `swtpm:host=127.0.0.1,port=2321`, or `mssim:host=127.0.0.1,port=2321`.

# PAM module arguments

`libpinpam.so` accepts the two standard password-stack arguments described in
`pam.conf(5)` / `pam_unix(8)`:

- `try_first_pass` — Before prompting for a PIN, try the authentication token
  cached by an earlier module in the stack (e.g. `pam_unix`). The cached token
  is only fed to the TPM if it actually parses as a valid PIN under the
  configured policy; non-digit strings or strings outside `pin_min_length` /
  `pin_max_length` are skipped without consuming a TPM attempt. If the cached
  token is a valid PIN but the TPM rejects it, the user is then prompted
  interactively for the remainder of the allowed attempts.
- `use_first_pass` — Force the module to authenticate exclusively with the
  cached token from the previous stack entry; never prompt. If no token is
  cached, or the token is not a valid PIN, or the TPM rejects it, the user is
  denied. This is the right choice when you want a single combined prompt
  (e.g. one password field that doubles as a PIN entry behind an earlier
  module).

Both arguments are off by default. When neither is set, pinpam ignores any
cached authtok and always prompts for the PIN itself, which is the historical
behaviour.

Example: configure pinpam to silently piggy-back on the password the user
already typed for the preceding module, prompting only if that token didn't
parse as a PIN:

```
auth  sufficient  libpinpam.so try_first_pass
```

Example: configure a single-prompt sudo stack where the user types one number
that both `pam_unix` and pinpam see:

```
auth  [success=ok default=ignore]  pam_unix.so   nullok
auth  sufficient                   libpinpam.so  use_first_pass
auth  required                     pam_deny.so
```

# Running the integration test suite

The `pinpam-core` crate ships an end-to-end test suite that drives the TPM
through `swtpm`. The suite focuses on backward compatibility: once a PIN has
been provisioned by any released version, it must remain verifiable. Tests
gracefully skip when `swtpm` is not on `PATH`.

```
# from a checkout, with swtpm installed (the devShell provides it)
cargo test -p pinpam-core --test swtpm_pin
```

# Building from source

You will need to have Rust and Cargo installed. You will also need the TPM2 development libraries installed (e.g., tpm2-tss-dev on Debian-based systems) and the clang tools installed.

To build pinpam, clone the repository and run:

```
cargo build --release
```

# Manual installation

First, ensure that a group exists that has access to the tpm device (e.g., `tss` or `tpm`), and that your user(s) are NOT members of that group. You can use udev rules to set the group ownership and permissions of the tpm device.

Place the resulting `libpinpam.so` in your PAM module directory (e.g., `/lib/security` or `/lib64/security`), and the `pinutil` binary in a directory of your choice (e.g., `/usr/local/bin`).
Add the pinpam PAM module to your desired PAM configuration files (e.g., `/etc/pam.d/common-auth`), taking care to configure it based on your needs and threat model.

Create a policy file as described above and ensure it is owned by root with permissions 0644

Then pick one of the two methods here to configure pinutil to access the TPM.

### Setgid method (marginally more secure)

Set the pinutil binary to be setgid owned by a group with access to the tpm device through group permissions.

```
sudo groupadd tss (if it doesn't exist)
chgrp tss /path/to/pinutil
chmod g+s /path/to/pinutil
```

Then add a new file to /etc/udev/rules.d with these contents:

```
# TPM device access for tss group
KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
```

### Setuid method (easier)

Alternatively, you can simply add the setuid bit to pinutil with

`chmod u+s /path/to/pinutil.`

# NixOS flake usage

The pinpam project includes a NixOS flake that can be used to easily configure pin
pam on a NixOS system.

First, add pinpam as an input to your flake:

```nix
{
  inputs.pinpam.url = "github:razelighter777/pinpam";
}
```

Then, enable pinpam in your NixOS configuration:

```nix
{
  lib,
  pkgs,
  inputs,
  config,
  ...
}:
let
  cfg = config.my.pinpam;
in
{
  imports = [ inputs.pinpam.nixosModules.default ];

  config = lib.mkIf cfg.enable {
    # Pinpam-specific configurations can go here
    security.pinpam = {
      enable = true;
      enableTpmAccess = true;
      enableSudoPin = true;
      enableSystemAuthPin = true;
      enableLoginPin = true;
      enableHyprlockPin=true;
      enablePolkitPin=true;
      enableKdePin=true;
      pinPolicy = {
        minLength = 4;
        maxLength = 6;
        maxAttempts = 5;
      };
    };
  };
}
```

Notable toggle options under `security.pinpam`:

- `enableSystemAuthPin`: Inserts pinpam as a `sufficient` module for the `system-auth` PAM stack so services that reuse `system-auth` accept TPM PINs.
- `enableLoginPin`: Adds pinpam as a `sufficient` rule to the `login` PAM service for console logins.
- `enableSudoPin`: Enables PIN authentication within the sudo PAM stack.
- `enableHyprlockPin`: Enables PIN authentication for the Hyprlock PAM service when available.
- `enablePolkitPin`: Enables PIN authenticaion for polkit and configures polkit sandboxing.
- `enableTpmAccess`: Configures groups and udev rules needed to run pinutil
- `enableKdePin`: Enables PIN authentication for the kde service (works for kdescreenlocker)

# Master-key: unlocking userspace wallets

pinpam can unlock a userspace secret store (KWallet, GNOME Keyring, `pam_gnupg`,
…) automatically at login, even when the user logs in with a PIN instead of
their password. A keyring's PAM module normally captures the login password from
`PAM_AUTHTOK` and uses it as the wallet key — but a PIN login never provides that
password, so the wallet stays locked.

The `libpinpam_master_key.so` module bridges this gap. After the auth decision
has been made, it overwrites `PAM_AUTHTOK` with a stable, TPM-bound per-user
token:

```
token = hex(HMAC(tpm_master_key, username))
```

A downstream keyring module then captures that token as the wallet key. Because
the token depends only on the username and a TPM-resident master key — not on
the login method — the wallet is keyed identically whether the user logged in
with a PIN or a password. (You re-key the wallet to this token once; see your
keyring's docs for changing the wallet password.)

## How the module behaves

`libpinpam_master_key.so` is a *side-effect* module, not an authenticator. Its
`pam_sm_authenticate` returns `PAM_IGNORE` on **every** path — success, failure,
or error — so it can never satisfy (or block) the auth decision regardless of
the control value an admin gives it. The worst case of any internal error is
that the wallet simply does not auto-unlock; a login is never granted or denied
because of this module. This is deliberate defence-in-depth against
misconfiguration.

Two ordering constraints follow from this:

1. It must run **after** the real auth decision, so the wallet is only unlocked
   for genuine logins (the keyring opens the session only on overall success).
2. It must run **before** the keyring module captures `PAM_AUTHTOK`, and after
   any module (such as nixpkgs' `unix-early`) that would otherwise overwrite the
   token first.

## The substack pattern

The tricky part is that the common auth methods are `sufficient`: on success
`pam_unix` (or pinpam) short-circuits the whole stack, skipping the master-key
and keyring stages entirely. The robust fix is to move the decision into its own
**substack**. A `sufficient` short-circuit inside a substack is confined to the
substack — it does not short-circuit the parent — so the parent can still run
the master-key and keyring stages afterwards.

Hand-written `/etc/pam.d` example (works with `pam_unix` and any `sufficient`
auth method). Replace the module paths with wherever pinpam is installed on your
distribution (e.g. `/lib/security` or `/usr/lib/security`). First, the decision
substack, `/etc/pam.d/pinpam-decide`:

```
# PIN-or-password decision. Each method is sufficient; its short-circuit stays
# confined to this substack. The trailing deny fails the substack (and thus the
# parent) only if every method above failed.
auth  sufficient  libpinpam.so  try_first_pass
auth  sufficient  pam_unix.so   try_first_pass likeauth
auth  requisite   pam_deny.so
```

Then reference it from the real service, e.g. `/etc/pam.d/sudo`:

```
auth  substack  pinpam-decide
auth  optional  libpinpam_master_key.so
auth  optional  pam_kwallet5.so
# ... your usual account / password / session lines ...
```

On success the substack returns success without short-circuiting the parent, so
master-key stamps the wallet token and `pam_kwallet5` captures it. On failure
the substack's `requisite pam_deny` fails the substack, and since nothing in the
parent then succeeds, auth is denied — no terminal `pam_deny` is needed (or
wanted) in the parent, because a substack cannot short-circuit it on success.

## NixOS configuration

The flake's NixOS module generates exactly this layout for you. Enabling
`security.pinpam.masterKey` for a service writes a `pinpam-decide-<service>`
substack, disables the inline success methods and the parent's terminal deny,
and reorders the keyring rules to run right after the master-key stage:

```nix
{
  security.pinpam = {
    enable = true;
    auth = {
      enable = true;
      services = [ "sudo" "login" ];
    };
    masterKey = {
      enable = true;
      services.login = {
        enable = true;
        # Auth methods whose success should route into the master-key stage.
        # Each is copied into the decision substack as `sufficient` and disabled
        # in the parent stack. List exactly the methods you use; add network /
        # identity methods (e.g. "systemd_home", "ldap", "sss") here too.
        successRules = [ "pinpam" "unix" ];
        # Keyring rules moved to run after master-key so they capture the
        # stamped token. Defaults to the common keyring/secret modules.
        postAuthRules = [ "kwallet" "gnome_keyring" "gnupg" ];
      };
    };
  };
}
```

Relevant options under `security.pinpam.masterKey`:

- `enable`: build and install `libpinpam_master_key.so`.
- `control`: PAM control for the master-key line itself (default `optional`;
  the module returns `PAM_IGNORE` regardless).
- `fallbackDenyOrder`: order used to anchor the injected rules when the service's
  deny rule order can't be read (default `13700`).
- `services.<name>.enable`: turn on the master-key flow for a PAM service.
- `services.<name>.successRules`: see the comment above. Note the module cannot
  read a rule's original `enable` while disabling it, so a name listed here is
  always copied into the substack — list only methods you actually use.
- `services.<name>.postAuthRules`: keyring/secret rules reordered after
  master-key. Names absent from the service become harmless disabled stubs.
- `services.<name>.denyAnchorRule`: existing rule used as the ordering anchor
  (default `"deny"`).

# Arch Linux : AUR Package

This package is also available in the AUR in the package pinpam-git, authored by raze_lighter777 (me).
You will need to manually configure the polkit service, as seen here:
https://github.com/RazeLighter777/pinpam/issues/4

# Special Thanks

Special thanks to creators of [rust-tss-esapi](https://github.com/parallaxsecond/rust-tss-esapi), the foundation of this utility, and all other tirelessly hardworking open source maintainers that made this project possible
