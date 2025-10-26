# pinpam

pinpam is a PAM module and credential utility to enable system-wide authentication with a secure pin. 

# Features
- Hardware-backed brute force protection
- Configurable number of allowed authentication failures.
- PIN resets
- NixOS flake with pam and udev configuration options. 

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
- A TPM2 (Trusted Platform Module) is required.
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