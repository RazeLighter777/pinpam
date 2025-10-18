# TPM Dictionary Attack Lockout Policy Configuration

## Overview
The PIN lockout policy is now managed through TPM's native dictionary attack protection. The policy is configured via a configuration file (`./policy`) and applied to the TPM using the `setup_pin --configure-lockout` command.

## How It Works

This implementation uses the TPM's built-in dictionary attack protection mechanism instead of custom NV storage. The TPM automatically:
- Tracks failed authentication attempts
- Enforces lockout when the threshold is exceeded
- Manages lockout recovery automatically

The policy file configures the TPM's native parameters:
- `max_attempts` → TPM's `newMaxTries` parameter
- `lockout_duration` → TPM's `newRecoveryTime` parameter (time in seconds to decrement counter by 1)

## Configuration File Format

The `policy` file should be in the same directory as the executables and contain:

```
# TPM Dictionary Attack Lockout Policy Configuration
max_attempts=N
lockout_duration=N
```

### Parameters

- **max_attempts**: Maximum number of failed PIN attempts before TPM lockout
  - Set to `0` to disable lockout entirely (sets TPM max_tries to maximum value)
  - Example: `max_attempts=3` allows 3 attempts before TPM locks
  - This configures TPM's dictionary attack counter threshold

- **lockout_duration**: Recovery time in seconds for TPM dictionary attack counter
  - This is the time it takes for the TPM to decrement the failure counter by 1
  - Set to `0` for manual recovery only (requires `setup_pin --unlock`)
  - Example: `lockout_duration=300` means counter decrements by 1 every 5 minutes
  - The TPM will automatically recover over time based on this setting

### Example Configurations

**Lenient** (5 attempts, 2 minute recovery per failed attempt):
```
max_attempts=5
lockout_duration=120
```

**Moderate** (3 attempts, 5 minute recovery per failed attempt):
```
max_attempts=3
lockout_duration=300
```

**Strict** (3 attempts, manual recovery only):
```
max_attempts=3
lockout_duration=0
```

**Disabled** (no lockout):
```
max_attempts=0
lockout_duration=0
```

## Applying the Configuration

After creating or modifying the policy file, you must apply it to the TPM:

```bash
sudo ./setup_pin --configure-lockout
```

This command:
- Reads the policy file
- Configures the TPM's native dictionary attack protection parameters
- Requires root privileges (uses TPM lockout hierarchy)

## How It Works

1. Administrator creates/modifies the `policy` file with desired settings
2. Administrator runs `setup_pin --configure-lockout` to apply settings to TPM
3. TPM's native dictionary attack protection enforces the policy
4. PAM authentication checks TPM lockout status before attempting verification
5. Failed attempts increment TPM's internal counter automatically
6. TPM handles recovery based on configured parameters

## Security Notes

- The policy file should be readable by all users but writable only by root
- Recommended permissions: `chmod 644 policy` and `chown root:root policy`
- The TPM's dictionary attack protection is hardware-enforced
- Policy changes require running `--configure-lockout` to take effect
- The TPM protects against TOCTOU attacks and race conditions natively

## Managing Lockouts

**Configure/reconfigure lockout policy:**
```bash
sudo ./setup_pin --configure-lockout
```

**Check TPM lockout status:**
The TPM maintains its own lockout state. Failed authentications will automatically trigger lockout based on configured parameters.

**Manually reset TPM lockout (emergency):**
```bash
sudo ./setup_pin --unlock
```

This resets the TPM's dictionary attack counter and clears lockout mode.

## Migration from Previous Version

If you're migrating from the custom lockout implementation:

1. The old per-user NV lockout indices (TPM_NV_LOCKOUT_BASE + uid) are no longer used
2. Run `setup_pin --clear <uid>` to remove old PIN data if needed (doesn't affect lockout anymore)
3. Configure the new TPM-wide lockout policy with `--configure-lockout`
4. The TPM now manages all lockout state natively

## Advantages of TPM Native Dictionary Attack Protection

- **Hardware-enforced**: TPM handles all lockout logic in hardware
- **Race condition immune**: No TOCTOU vulnerabilities
- **Atomic operations**: TPM guarantees atomic counter updates
- **Persistent**: Survives reboots and system crashes
- **Standardized**: Uses TPM 2.0 specification dictionary attack protection
- **No custom NV storage**: Reduces TPM NV wear and complexity
