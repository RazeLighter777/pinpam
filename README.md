# PinPAM - TPM-backed PIN Authentication

A PAM module that uses TPM 2.0 to securely store and verify PINs using HMAC operations.

## Features

- **TPM-backed Security**: PINs are stored as HMACs computed by a TPM-resident key
- **Lockout Protection**: Configurable failed attempt limits with temporary or permanent lockouts
- **Atomic Operations**: TOCTOU-safe lockout checking
- **Secure Logging**: All authentication events logged to syslog/journalctl
- **UID-based Storage**: Each user's PIN is stored in a separate TPM NV index

## Building

### With Nix Flakes

```bash
# Build the package
nix build

# Enter development shell
nix develop

# Build with CMake in dev shell
cmake -B build
cmake --build build
```

### Without Nix

Requirements:
- CMake >= 3.10
- Linux PAM development headers
- TPM2-TSS libraries
- OpenSSL

```bash
cmake -B build
cmake --build build
```

## Installation

### NixOS

Add to your `flake.nix`:

```nix
{
  inputs.pinpam.url = "github:yourusername/pinpam";

  outputs = { self, nixpkgs, pinpam, ... }: {
    nixosConfigurations.yourhostname = nixpkgs.lib.nixosSystem {
      modules = [
        pinpam.nixosModules.default
        {
          security.pinpam = {
            enable = true;
            
            # Enable TPM access for tss group (default: true)
            enableTpmAccess = true;
            
            # Enable TPM PIN authentication for sudo (default: false)
            enableSudoPin = true;
            
            # Optional: Specify lockout policy file
            policyFile = ./policy;  # or /path/to/your/policy
          };
          
          # Add users to tss group so they can use setup_pin
          users.users.youruser.extraGroups = [ "tss" ];
        }
      ];
    };
  };
}
```

The NixOS module will:
- Install the PAM module to `/lib/security/pam_pinpam.so`
- Create a setgid wrapper for `setup_pin` at `/run/wrappers/bin/setup_pin` with the `tss` group
- Ensure the `tss` group exists
- Add udev rules to give the `tss` group read/write access to `/dev/tpm*` and `/dev/tpmrm*`
- Optionally configure sudo to accept TPM PIN authentication (if `enableSudoPin = true`)
- Optionally install lockout policy to `/etc/pinpam/policy` (if `policyFile` is set)

#### NixOS Module Options

- `security.pinpam.enable`: Enable the pinpam module (default: `false`)
- `security.pinpam.package`: The pinpam package to use (default: auto-detected)
- `security.pinpam.enableTpmAccess`: Add udev rules for TPM device access (default: `true`)
- `security.pinpam.enableSudoPin`: Enable TPM PIN authentication for sudo with priority 10 lower than unix auth (default: `false`)
- `security.pinpam.policyFile`: Path to lockout policy configuration file to install at `/etc/pinpam/policy` (default: `null`)

### Manual Installation

```bash
# Install PAM module
sudo cp build/libpinpam.so /usr/lib/security/

# Install setup_pin with proper permissions
sudo cp build/setup_pin /usr/local/bin/
sudo chown root:tss /usr/local/bin/setup_pin
sudo chmod 2755 /usr/local/bin/setup_pin

# Ensure tss group exists
sudo groupadd -r tss || true

# Add udev rules for TPM access
sudo tee /etc/udev/rules.d/70-tpm-access.rules << 'EOF'
# TPM device access for tss group
KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
EOF

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Add users to tss group
sudo usermod -aG tss youruser
```

## Configuration

### TPM Dictionary Attack Lockout Policy

This implementation uses TPM's native dictionary attack protection instead of custom lockout tracking.

Create `/etc/pinpam/policy` (or `./policy` for testing):

```
# Maximum failed attempts (0 = disabled)
max_attempts=3

# Recovery time in seconds (time for TPM to decrement counter by 1)
# Set to 0 for manual recovery only
lockout_duration=300
```

After creating the policy file, apply it to the TPM:

```bash
sudo setup_pin --configure-lockout
```

The TPM will then enforce dictionary attack protection using its hardware-backed counters.

See [POLICY_CONFIG.md](POLICY_CONFIG.md) for detailed configuration information.

### PAM Configuration

#### NixOS (Automatic)

With `enableSudoPin = true`, sudo is automatically configured to accept TPM PIN authentication.

#### Manual Configuration

Add to your PAM configuration (e.g., `/etc/pam.d/sudo`):

```
# Try TPM PIN first, fall back to password
auth    sufficient    pam_pinpam.so
auth    include       system-auth
```

For required authentication (no fallback):

```
auth    required      pam_pinpam.so
```

## Usage

### Setting a PIN

```bash
# Set PIN for current user
setup_pin

# As root, set PIN for another user
sudo setup_pin
```

### Configuring TPM Lockout Policy (Root Only)

```bash
# Apply lockout policy from ./policy or /etc/pinpam/policy to TPM
sudo setup_pin --configure-lockout
```

### Unlocking TPM (Root Only)

```bash
# Reset TPM dictionary attack lockout counter
sudo setup_pin --unlock
```

This clears the TPM's dictionary attack counter and removes lockout mode for all users.

### Clearing PIN Data (Root Only)

```bash
# Delete PIN data for a specific UID
sudo setup_pin --clear 1000
```

### Viewing Logs

```bash
# View all pinpam logs
sudo journalctl -t pam_pinpam -t setup_pin

# Follow logs in real-time
sudo journalctl -t pam_pinpam -t setup_pin -f

# View only warnings and errors
sudo journalctl -t pam_pinpam -t setup_pin -p warning

# View logs from today
sudo journalctl -t pam_pinpam -t setup_pin --since today
```

## Security Features

### PIN Storage

- PINs are never stored in plaintext
- HMAC key is generated and stored in TPM persistent storage
- Each user's PIN HMAC is stored in a dedicated TPM NV index

### Lockout Protection

- Configurable maximum failed attempts
- Temporary lockouts with automatic expiration
- Permanent lockouts option
- Atomic counter increment prevents TOCTOU attacks

### Logging

All security events are logged to syslog with facility `LOG_AUTHPRIV`:

- Authentication attempts
- Successful authentications
- Failed authentications (with attempt counts)
- Lockouts (temporary and permanent)
- PIN changes
- PIN clears
- Unlock operations

### UID Validation

- Integer overflow protection in NV index calculation
- Maximum safe UID: 65535 (prevents collision with reserved TPM space)

## Architecture

### Components

1. **libpinpam.so**: PAM module for authentication
2. **setup_pin**: Utility for PIN management (setgid to `tss` group)
3. **libtpm_common.a**: Shared TPM operations library

### TPM Resources

- **HMAC Key**: Persistent handle `0x81010001`
- **PIN Storage**: NV indices starting at `0x01500020 + UID`
- **Lockout Data**: NV indices starting at `0x01500100 + UID`

### Dependencies

- TPM 2.0 device (`/dev/tpm0` or `/dev/tpm0rm0`)
- Linux PAM
- TPM2-TSS (ESAPI)
- OpenSSL (for constant-time comparison)

## Troubleshooting

### TPM Access Denied

Ensure you have access to the TPM device:

```bash
# Check permissions
ls -l /dev/tpm*

# Add user to tss group
sudo usermod -aG tss youruser

# Reboot or re-login for group changes to take effect
```

### HMAC Key Already Exists

If you get errors about the persistent handle already existing:

```bash
# Remove old key (requires root/TPM owner auth)
sudo tpm2_evictcontrol -C o -c 0x81010001
```

### Viewing TPM Resources

```bash
# List persistent handles
tpm2_getcap handles-persistent

# Read public area of HMAC key
tpm2_readpublic -c 0x81010001
```

## License

MIT License - See LICENSE file for details
