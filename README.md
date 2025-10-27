# pinpam

pinpam is a PAM module and credential utility to enable system-wide authentication with a secure TPM2-backed pin. 

# Features
- Hardware-backed brute force protection
- Configurable number of allowed authentication failures.
- PIN resets
- NixOS flake with pam and udev configuration options. 

# FAQ
- What does this program do? : pinpam lets you use a pin to authenticate yourself on linux. This could be for logging in, sudo, or any other service supported by PAM (pluggable authentication modules).
- How is this different than setting my password to a number (and using faillock)? : pinpam stores your pin in the TPM rather than in /etc/shadow. Storing a pin in /etc/shadow is a bad idea, if that file gets leaked, depending on the length of the pin, it can be trivial to brute force and reuse those credentials on another system. pinpam protects against hash dumping attacks and credential reuse.
- How do I reset/change a pin? : User's can change their own pins if they haven't been locked out with the pinutil command. A locked out pin must be manually reset by root. 
- Isn't a pin less secure than a password? : It depends. Generally a pin is less secure than a strong password, but they can be more convenient and easier for users to embrace. You should consider your threat model when implementing any authentication service. 
- Can I set a lockout duration? : You cannot at this time. I wanted this feature, but TPM2 afaik doesn't support this with pinfail indexes. Global dictionary attack does, but this would get rid of per user lockouts. If you have ideas on how this can be implemented please open up an issue. 
-  Will changing the lockout policy file affect existing pins? : No, users must change their pins to reload a new lockout policy. Admins can accomplish this by deleting all user pins.
- Can you support OTP? : I'd like to and this is a subject of research for me. Pull requests are welcome.
- License? : This project is licensed under the GPLv3. 
- Packaging? : Currently this project is only in a nixOS flake. You can manually build it and install the binaries if you wish, it should be broadly compatible. Pull requests welcome. 

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
To mitigate this, pinpam uses a TPM2 policy to restrict the PinFail index to only being written once. \

See SECURITY.md for a summary of the pinpam threat model

# Important Considerations
- ⚠️⚠️⚠️ Ensure that no user on the system other than root has direct access to the TPM device (e.g., /dev/tpm0 or /dev/tpmrm0). Direct access would allow users to delete/reset other users' pins, bypassing pinpam's security features.
- A TPM2 (Trusted Platform Module) is required.
- No not give user's access to the tpm device, or they could delete/reset (but not read or brute force) other user's pins
- Losing access to the TPM (or clearing it) will result in the loss of the stored PIN and any associated data.
- You cannot reset a lockout without clearing the pin. This is a security feature to prevent brute-force attacks.
- ⚠️ Ensure you know what you are doing before marking pinpam as `required` in PAM configurations. Lockout could prevent legitimate access to the system and opens a risk of denial of service attacks. `sufficient` with a fallback method (e.g., regular unix auth) is recommended for most use cases.
- pinutil is designed to operate as a setgid binary. It should be set to a group with rw access to /dev/tpmrm0 (e.g., `tpm` or `tss`), assuming udev rules are set up correctly. See the NixOS flake for an example, which does this automatically.

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
  -h, --help     Print help
  -V, --version  Print version
```

# Configuration syntax
Configuration file must be named policy. pinpam checks in ./policy and /etc/pinpam/policy. For security, it MUST be owned by root and have permissions 0644.
Example policy file:
```
pin_min_length=4
pin_max_length=6
pin_lockout_max_attempts=5
pinutil_path=/nix/store/p2799cpnhk2malpmp7ilqvxg76gajlh9-pinpam-0.1.0/bin/pinutil
```
Where 
pin_min_length = minimum length of pin
pin_max_length = maximum length of pin
pin_lockout_max_attempts = number of allowed failed attempts before lockout
pinutil_path = path to pinutil binary to prevent path overwrite attacks. (mandatory)

# Building from source
You will need to have Rust and Cargo installed. You will also need the TPM2 development libraries installed (e.g., tpm2-tss-dev on Debian-based systems) and the clang tools installed.

To build pinpam, clone the repository and run:
```
cargo build --release
```

# Manual installation

First, ensure that a group exists that has access to the tpm device (e.g., `tss` or `tpm`), and that your user is a member of that group to build the project. You can use udev rules to set the group ownership and permissions of the tpm device.

Place the resulting `libpinpam.so` in your PAM module directory (e.g., `/lib/security` or `/lib64/security`), and the `pinutil` binary in a directory of your choice (e.g., `/usr/local/bin`).
Add the pinpam PAM module to your desired PAM configuration files (e.g., `/etc/pam.d/common-auth`), taking care to configure it based on your needs and threat model.

Create a policy file as described above and ensure it is owned by root with permissions 0644, and set the pinutil binary to be setgid owned by a group with access to the tpm device through group permissions.

```
chgrp tss /path/to/pinutil
chmod g+s /path/to/pinutil
```


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
      enableHyprlockPin=true;
      pinPolicy = {
        minLength = 4;
        maxLength = 6;
        maxAttempts = 5;
      };
    };
  };
}
```

This will enable pinpam system-wide, including for sudo and Hyprlock (if installed). Adjust the `pinPolicy` values as needed for your security requirements. This will generate the necessary PAM configurations and udev rules automatically, and create the groups needed for tpm access.