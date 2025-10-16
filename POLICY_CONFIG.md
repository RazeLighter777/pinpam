# Lockout Policy Configuration

## Overview
The PIN lockout policy is now managed through a simple configuration file (`./policy`) instead of being stored in the TPM or passed as PAM module arguments.

## Configuration File Format

The `policy` file should be in the same directory as the executables and contain:

```
# PIN Lockout Policy Configuration
max_attempts=N
lockout_duration=N
```

### Parameters

- **max_attempts**: Maximum number of failed PIN attempts before lockout
  - Set to `0` to disable lockout entirely
  - Example: `max_attempts=3` allows 3 attempts before locking

- **lockout_duration**: Time in seconds to lock out after max_attempts is reached
  - Set to `0` for permanent lockout (requires root to unlock with `./setup_pin --unlock <uid>`)
  - Example: `lockout_duration=300` locks for 5 minutes
  - Example: `lockout_duration=0` locks permanently

### Example Configurations

**Lenient** (5 attempts, 2 minute lockout):
```
max_attempts=5
lockout_duration=120
```

**Moderate** (3 attempts, 5 minute lockout):
```
max_attempts=3
lockout_duration=300
```

**Strict** (3 attempts, permanent lockout):
```
max_attempts=3
lockout_duration=0
```

**Disabled** (no lockout):
```
max_attempts=0
lockout_duration=0
```

## How It Works

1. Both PAM authentication and `setup_pin` read the policy file at runtime
2. If the file doesn't exist, lockout is disabled (max_attempts=0)
3. The TPM stores only the state (failed_attempts, unlock_time)
4. The policy file is checked on every authentication/PIN change attempt
5. This allows changing policy without modifying PAM configuration or recompiling

## Security Notes

- The policy file should be readable by all users but writable only by root
- Recommended permissions: `chmod 644 policy` and `chown root:root policy`
- Changes to the policy file take effect immediately on next authentication
- Existing lockouts continue until they expire or are manually cleared

## Managing Lockouts

**Check if a user is locked out:**
```bash
# No direct command, but authentication will show lockout message
```

**Manually unlock a user (requires root):**
```bash
sudo ./setup_pin --unlock <uid>
```

**Clear all data for a user (requires root):**
```bash
sudo ./setup_pin --clear <uid>
```
