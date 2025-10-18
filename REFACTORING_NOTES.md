# Refactoring to TPM Native Dictionary Attack Protection

## Overview
This refactoring replaces the custom lockout implementation (using per-user NV indices) with TPM's native dictionary attack protection mechanism.

## Major Changes

### 1. Header File (`include/tpm_common.h`)
- **Removed**: `TPM_NV_LOCKOUT_BASE` define (no longer need per-user lockout storage)
- **Removed**: `lockout_data_t` structure (custom lockout state)
- **Removed**: Old lockout management functions:
  - `read_lockout_data()`
  - `write_lockout_data()`
  - `atomic_lockout_check_and_increment()`
  - `clear_lockout()`

- **Added**: New TPM native lockout functions:
  - `configure_tpm_lockout()` - Configure TPM dictionary attack parameters
  - `reset_tpm_lockout()` - Reset TPM dictionary attack lockout
  - `check_tpm_lockout_status()` - Query TPM lockout state

- **Updated**: `lockout_policy_t` comment to clarify it configures TPM native parameters

### 2. Implementation File (`src/tpm_common.c`)
- **Removed**: All custom lockout state management code
- **Removed**: Per-user NV index calculations for lockout data
- **Removed**: Duplicate `read_lockout_policy()` function

- **Added**: `configure_tpm_lockout()` 
  - Uses `Esys_DictionaryAttackParameters()` to configure TPM
  - Maps `max_attempts` → `newMaxTries`
  - Maps `lockout_duration` → `newRecoveryTime`
  - Uses `ESYS_TR_RH_LOCKOUT` hierarchy with `ESYS_TR_PASSWORD` auth

- **Added**: `reset_tpm_lockout()`
  - Uses `Esys_DictionaryAttackLockReset()` to clear TPM lockout
  - Requires lockout hierarchy authorization

- **Added**: `check_tpm_lockout_status()`
  - Uses `Esys_GetCapability()` to query TPM properties
  - Checks `TPM2_PT_LOCKOUT_COUNTER` and `TPM2_PT_MAX_AUTH_FAIL`
  - Returns 0=not locked, 1=locked, -1=error

- **Updated**: `validate_uid_safe()` - Removed lockout index validation

### 3. PAM Module (`src/lib.c`)
- **Removed**: Policy file reading (no longer needed per-auth)
- **Removed**: Per-user lockout index calculation
- **Removed**: `atomic_lockout_check_and_increment()` call
- **Removed**: Custom lockout state tracking

- **Added**: `check_tpm_lockout_status()` call before authentication
- **Updated**: Success path now calls `reset_tpm_lockout()` 
- **Simplified**: Failed auth path - TPM handles lockout automatically

### 4. Setup Utility (`src/setup_pin.c`)
- **Removed**: `--unlock <uid>` option (replaced with global `--unlock`)
- **Removed**: Per-user lockout index handling
- **Removed**: Custom lockout data read/write operations

- **Added**: `--unlock` option (no argument) - resets TPM dictionary attack lockout
- **Added**: `--configure-lockout` option - applies policy file to TPM
- **Updated**: `--clear <uid>` - now only deletes PIN data, not lockout data
- **Updated**: PIN verification - checks TPM lockout status instead of custom state
- **Simplified**: Success path calls `reset_tpm_lockout()` instead of custom clear

### 5. Documentation (`POLICY_CONFIG.md`)
- **Completely rewritten** to document TPM native dictionary attack protection
- Explains how policy file maps to TPM parameters
- Documents new `--configure-lockout` command
- Added migration guide from old implementation
- Added advantages section explaining benefits

## Key Behavioral Changes

### Before (Custom Implementation)
1. Each user had their own NV lockout index (TPM_NV_LOCKOUT_BASE + uid)
2. Custom code managed `failed_attempts` and `unlock_time` in NV storage
3. Lockout state checked/updated per-user during authentication
4. Vulnerable to TOCTOU despite atomic update attempts
5. Required manual NV storage management and cleanup

### After (TPM Native)
1. TPM manages single global dictionary attack counter
2. TPM hardware enforces lockout automatically
3. PAM module only checks if TPM is in lockout before attempting auth
4. TPM guarantees atomic operations (no TOCTOU possible)
5. No custom NV storage needed for lockout state

## Security Improvements

1. **Hardware-enforced**: TPM manages all lockout logic in tamper-resistant hardware
2. **Race condition immune**: TPM guarantees atomic counter operations
3. **Standards-compliant**: Uses TPM 2.0 specification dictionary attack protection
4. **Reduced attack surface**: Removed ~300 lines of custom lockout code
5. **No TOCTOU vulnerabilities**: TPM handles all state transitions atomically

## Usage Changes

### Configuring Lockout Policy
**Before**: Policy file was read on every authentication
**After**: Policy must be applied to TPM explicitly:
```bash
# Edit policy file
vim ./policy

# Apply to TPM
sudo ./setup_pin --configure-lockout
```

### Unlocking After Lockout
**Before**: Unlock specific user
```bash
sudo ./setup_pin --unlock <uid>
```

**After**: Reset TPM dictionary attack lockout (global)
```bash
sudo ./setup_pin --unlock
```

### Clearing User Data
**Before**: Cleared both PIN and lockout data
```bash
sudo ./setup_pin --clear <uid>
```

**After**: Only clears PIN data (lockout is TPM-wide now)
```bash
sudo ./setup_pin --clear <uid>
```

## Migration Path

For existing deployments:

1. **Policy Configuration**: 
   - Existing policy file format unchanged
   - Run `sudo ./setup_pin --configure-lockout` to apply to TPM

2. **Lockout Data**:
   - Old per-user lockout NV indices (TPM_NV_LOCKOUT_BASE + uid) are ignored
   - No migration needed - TPM starts fresh
   - Can optionally clean up old NV indices to free TPM NV storage

3. **Authentication**:
   - Works immediately with new code
   - TPM will enforce lockout based on configured parameters

## Testing Recommendations

1. **Test lockout behavior**:
   ```bash
   # Configure policy
   echo "max_attempts=3" > policy
   echo "lockout_duration=60" >> policy
   sudo ./setup_pin --configure-lockout
   
   # Try 3 incorrect PINs to trigger lockout
   # Verify lockout is enforced
   ```

2. **Test lockout reset**:
   ```bash
   sudo ./setup_pin --unlock
   # Verify authentication works again
   ```

3. **Test policy changes**:
   ```bash
   # Change policy
   vim policy
   sudo ./setup_pin --configure-lockout
   # Verify new parameters take effect
   ```

## Files Modified

- `include/tpm_common.h` - API changes
- `src/tpm_common.c` - Implementation of TPM native functions
- `src/lib.c` - PAM module authentication flow
- `src/setup_pin.c` - PIN setup utility
- `POLICY_CONFIG.md` - User documentation

## Lines of Code Impact

- **Removed**: ~300 lines of custom lockout management
- **Added**: ~165 lines of TPM native lockout integration
- **Net**: ~135 lines reduction in codebase complexity

## Build System

No changes required to CMakeLists.txt or build configuration. The refactoring uses existing TPM2-TSS APIs that were already linked.
