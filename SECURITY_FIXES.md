# Security Fixes Implementation

## Fix #1: TOCTOU (Time-of-Check to Time-of-Use) Race Condition in Lockout

### Vulnerability
The original code had a race condition between checking the lockout status and verifying the PIN:
1. Thread A checks lockout → passes
2. Thread B checks lockout → passes (same time)
3. Both threads proceed to verify PIN
4. Multiple attempts could bypass lockout limits

### Fix Implementation
Implemented **atomic lockout check and increment** in `src/lib.c`:

```c
static int atomic_lockout_check_and_increment(ESYS_CONTEXT *esys, 
                                               TPM2_HANDLE lockout_index,
                                               uint32_t max_attempts, 
                                               uint32_t lockout_time,
                                               lockout_data_t *out_lockout)
```

**Key Changes:**
- **Increment BEFORE PIN verification** - The attempt counter is incremented atomically before any PIN check
- **Single write operation** - The incremented counter is written to TPM immediately
- **Fail-closed on errors** - Any TPM write failure denies authentication
- **Clear on success only** - Successful authentication clears the counter

**Flow:**
1. Read current lockout state
2. Check if already locked out → deny if yes
3. **Increment attempt counter atomically**
4. Write incremented counter to TPM
5. Check if this increment causes lockout
6. Only proceed with PIN verification if not locked out
7. On successful auth, clear the counter

This ensures that even with concurrent authentication attempts, each one increments the counter, and the lockout is enforced correctly.

---

## Fix #2: Integer Overflow in NV Index Calculation

### Vulnerability
The original code calculated TPM NV indices without validating UIDs:
```c
uint32_t user_nv_index = TPM_NV_INDEX + uid;  // Could overflow!
```

Large UIDs could:
- Overflow and wrap around to low addresses
- Collide with other users' indices
- Collide with reserved TPM NV space (0x01800000+)
- Access system critical NV indices

### Fix Implementation

#### 1. Added Constants (`include/tpm_common.h`)
```c
#define MAX_SAFE_UID 0x0000FFFFU  // 65535 - maximum safe UID value
```

This limits the NV space to:
- PIN data: 0x01500020 to 0x0150FFFF
- Lockout data: 0x01500100 to 0x0151FFFF
- Well below reserved TPM space at 0x01800000

#### 2. Validation Function (`src/tpm_common.c`)
```c
int validate_uid_safe(uid_t uid) {
    // Check UID is within safe range
    if (uid > MAX_SAFE_UID) {
        return -1;
    }
    
    // Check for integer overflow
    uint32_t test_pin_index = TPM_NV_INDEX + uid;
    uint32_t test_lockout_index = TPM_NV_LOCKOUT_BASE + uid;
    
    if (test_pin_index < TPM_NV_INDEX || 
        test_lockout_index < TPM_NV_LOCKOUT_BASE) {
        return -1;  // Overflow detected
    }
    
    // Check we don't collide with reserved TPM space
    if (test_pin_index >= 0x01800000U || 
        test_lockout_index >= 0x01800000U) {
        return -1;
    }
    
    return 0;  // Safe
}
```

#### 3. Applied Validation in All Entry Points

**`src/lib.c` - PAM authentication:**
```c
uid_t uid = pwd->pw_uid;

if (validate_uid_safe(uid) != 0) {
    fprintf(stderr, "UID %u is not safe for NV index calculation\n", uid);
    OPENSSL_cleanse(pin, sizeof(pin));
    return PAM_AUTH_ERR;
}

uint32_t user_nv_index = TPM_NV_INDEX + uid;
uint32_t user_lockout_index = TPM_NV_LOCKOUT_BASE + uid;
```

**`src/setup_pin.c` - Three validation points:**
1. Regular PIN setup/change (current user)
2. Unlock mode (--unlock <uid>)
3. Clear mode (--clear <uid>)

### Security Benefits
- **Prevents overflow attacks** - Malicious UIDs cannot cause wraparound
- **Prevents collision attacks** - Each user has guaranteed unique space
- **Protects reserved space** - Cannot access TPM system areas
- **Defense in depth** - Multiple validation checks ensure safety

---

## Testing Recommendations

### Test TOCTOU Fix
1. Run concurrent authentication attempts:
   ```bash
   for i in {1..10}; do pamtester service user authenticate & done
   ```
2. Verify lockout triggers correctly after max attempts
3. Ensure no race condition allows bypass

### Test Overflow Protection
1. Test with boundary UIDs:
   ```bash
   sudo useradd -u 65535 testuser1  # Should work
   sudo useradd -u 65536 testuser2  # Should be rejected
   ```
2. Verify validation error messages
3. Test that normal UIDs (0-60000) work correctly

### Test Edge Cases
- UID = 0 (root)
- UID = 65535 (max safe)
- UID = 65536 (should fail)
- UID = 4294967295 (maximum uint32_t, should fail)

---

## Remaining Vulnerabilities

These fixes address issues #1 and #2. The following high-priority issues remain:

- **#3**: Lockout bypass via direct NV manipulation
- **#4**: Missing authentication on NV operations (weak NV attributes)
- **#5**: Weak hash storage without salt (rainbow table attacks)
- **#6**: Memory not zeroed after free (some locations)
- **#8**: Root can bypass all security

Consider implementing these fixes in future updates.
