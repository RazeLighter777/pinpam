# Security Audit Report - PIN PAM Module
**Date:** October 16, 2025  
**Auditor:** Security Analysis  
**Codebase:** TPM-based PIN PAM Authentication Module

---

## Executive Summary

This security audit evaluated a PAM module that implements PIN-based authentication using a TPM (Trusted Platform Module) for credential storage. The codebase demonstrates good security practices in several areas but has **CRITICAL vulnerabilities** that must be addressed before production deployment.

**Overall Risk Level:** ⚠️ **HIGH**

### Key Findings
- ✅ **2 Critical Issues Already Fixed** (TOCTOU race, integer overflow)
- ❌ **6 Critical/High Severity Issues Remain**
- ⚠️ **4 Medium Severity Issues**
- ℹ️ **5 Low Severity/Best Practice Improvements**

---

## CRITICAL VULNERABILITIES (Must Fix Before Production)

### 1. ❌ CRITICAL: Weak TPM NV Attributes Allow Direct Manipulation
**Severity:** CRITICAL  
**CWE:** CWE-306 (Missing Authentication for Critical Function)

**Issue:**
```c
// src/tpm_common.c:167
.attributes = (TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | 
              TPMA_NV_AUTHREAD | TPMA_NV_NO_DA),
```

The NV indices use `TPMA_NV_AUTHREAD` which allows **ANY user** to read PIN hashes directly from the TPM without authentication. Combined with `TPMA_NV_OWNERWRITE`, root can also modify any user's credentials.

**Attack Vectors:**
1. **Offline Hash Extraction:** Any user can read `/dev/tpm0rm0` and extract all PIN hashes
2. **Brute Force Attack:** Attacker extracts hash and brute forces offline (no rate limiting)
3. **Credential Manipulation:** Root can set arbitrary PINs for any user
4. **Lockout Bypass:** Attacker with TPM access can reset lockout counters

**Proof of Concept:**
```bash
# Any user can read PIN hash directly
tpm2_nvread 0x01500020  # Extracts user 0's PIN hash
# Brute force offline with hashcat/john
```

**Recommendation:**
```c
// Use password-based authentication
.attributes = (TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD | 
              TPMA_NV_POLICYWRITE | TPMA_NV_POLICYREAD |
              TPMA_NV_NO_DA),
```
- Set NV auth policy requiring user credential
- Store per-user auth in TPM hierarchy
- Use `TPMA_NV_WRITTEN_ONCE` for critical data

---

### 2. ❌ CRITICAL: Unsalted Hash Storage Vulnerable to Rainbow Tables
**Severity:** CRITICAL  
**CWE:** CWE-759 (Use of One-Way Hash without a Salt)

**Issue:**
```c
// src/lib.c:127
unsigned char pin_hash[SHA256_DIGEST_LENGTH];
sha256_hash((unsigned char*)pin, strlen(pin), pin_hash);
```

PINs are hashed with SHA-256 without any salt. Since PINs are typically short (4-8 digits), this is vulnerable to:

**Attack Vectors:**
1. **Rainbow Table Attack:** Pre-computed hash tables for all 4-8 digit PINs
2. **Dictionary Attack:** Common PINs (1234, 0000, password) can be looked up instantly
3. **No Per-User Protection:** Same PIN → same hash across all users

**Impact:**
- All 4-digit PINs (10,000 combinations) can be hashed in milliseconds
- Rainbow tables for common PINs are readily available online
- Compromising one hash file reveals PINs for all users with same PIN

**Recommendation:**
```c
// Use PBKDF2, bcrypt, or Argon2 with per-user salt
#include <openssl/kdf.h>

// Store in NV: [salt(16 bytes)][hash(32 bytes)]
unsigned char salt[16];
RAND_bytes(salt, sizeof(salt));

unsigned char derived_key[32];
PKCS5_PBKDF2_HMAC(pin, strlen(pin), 
                  salt, sizeof(salt),
                  100000,  // Iterations
                  EVP_sha256(),
                  sizeof(derived_key), derived_key);
```

---

### 3. ❌ CRITICAL: Root Privilege Escalation Bypass
**Severity:** CRITICAL  
**CWE:** CWE-250 (Execution with Unnecessary Privileges)

**Issue:**
```c
// src/setup_pin.c:299
if (!is_root) {
    // Must verify current PIN
} else {
    printf("Running as root - current PIN verification and lockout checks bypassed\n");
}
```

Root can:
1. Set/change any user's PIN without knowing current PIN
2. Bypass all lockout mechanisms
3. Clear lockout data for any user
4. Read/modify TPM data freely

**Attack Scenario:**
```bash
# Attacker gains temporary root access
sudo ./setup_pin  # Changes victim's PIN
sudo ./setup_pin --clear 1000  # Deletes user's authentication
```

**Recommendation:**
- **Require current PIN even for root** (use `pam_authenticate` or direct verification)
- Implement audit logging for all root operations
- Add `--force` flag with mandatory audit trail for emergency access
- Consider separating "setup" from "admin" operations

---

### 4. ❌ HIGH: Race Condition in PIN Verification vs Lockout Clear
**Severity:** HIGH  
**CWE:** CWE-367 (Time-of-Check Time-of-Use Race Condition)

**Issue:**
```c
// src/lib.c:135-145
if (consttime_eq(pin_hash, nv_data, SHA256_DIGEST_LENGTH)) {
    ret = PAM_SUCCESS;
    clear_lockout(esys_ctx, user_lockout_index);  // ← Race window
} else {
    ret = PAM_AUTH_ERR;
}
```

**Race Window:**
1. Thread A: PIN verifies successfully → sets `ret = PAM_SUCCESS`
2. Thread B: PIN verifies successfully → sets `ret = PAM_SUCCESS`
3. Thread A: Calls `clear_lockout()` (async)
4. Thread B: Calls `clear_lockout()` (async)
5. If clear fails for one thread, lockout may not be properly cleared

**More Serious:**
Between increment and successful clear, another thread could check lockout status and see stale data.

**Recommendation:**
```c
// Atomic success path
if (consttime_eq(pin_hash, nv_data, SHA256_DIGEST_LENGTH)) {
    // Clear lockout BEFORE returning success
    if (clear_lockout(esys_ctx, user_lockout_index) != TSS2_RC_SUCCESS) {
        // Log warning but still allow auth (fail-open for usability)
        syslog(LOG_WARNING, "Failed to clear lockout for UID %u", uid);
    }
    ret = PAM_SUCCESS;
}
```

---

### 5. ❌ HIGH: Hardcoded Policy File Path
**Severity:** HIGH  
**CWE:** CWE-426 (Untrusted Search Path)

**Issue:**
```c
// src/lib.c:53
read_lockout_policy("./policy", &policy);

// src/setup_pin.c:335
read_lockout_policy("./policy", &policy);
```

Relative path `./policy` is resolved from **current working directory**, not binary location.

**Attack Scenario:**
```bash
# Attacker creates malicious policy in victim's directory
cd /tmp
echo "max_attempts=999999" > policy
echo "lockout_duration=0" >> policy

# Victim runs from /tmp
cd /tmp
sudo systemctl restart <service>  # PAM loads ./policy from /tmp!
```

**Impact:**
- Attacker disables lockout by creating policy file in vulnerable location
- Different behavior depending on CWD
- Privilege escalation via policy injection

**Recommendation:**
```c
#define POLICY_FILE "/etc/pinpam/policy"

// Or use PAM module arguments:
read_lockout_policy(argv[0], &policy);  // Pass via PAM config
```

---

## HIGH SEVERITY ISSUES

### 6. ❌ HIGH: Missing Memory Sanitization in Error Paths
**Severity:** HIGH  
**CWE:** CWE-244 (Improper Clearing of Heap Memory Before Release)

**Issue:**
Multiple error paths don't properly cleanse sensitive data:

```c
// src/lib.c:73 - Early return without cleansing
if (pwd == NULL) {
    fprintf(stderr, "Failed to get user info for %s\n", username);
    OPENSSL_cleanse(pin, sizeof(pin));
    return PAM_AUTH_ERR;  // ✓ Good
}

// src/lib.c:80 - UID validation early return
if (validate_uid_safe(uid) != 0) {
    fprintf(stderr, "UID %u is not safe...\n", uid);
    OPENSSL_cleanse(pin, sizeof(pin));  // ✓ Good
    return PAM_AUTH_ERR;
}

// BUT: src/setup_pin.c:355 - Missing cleanse on error
if (error_code != 0x018B && error_code != TPM2_RC_HANDLE) {
    fprintf(stderr, "Error checking existing PIN: 0x%X\n", rc);
    cleanup_tpm(&esys_ctx, &tcti_ctx);
    return 1;  // ❌ current_pin not cleansed!
}
```

**Recommendation:**
- Audit ALL return paths
- Use `goto cleanup` pattern consistently
- Add automated testing for memory sanitization

---

### 7. ❌ HIGH: Insecure Policy File Parsing
**Severity:** HIGH  
**CWE:** CWE-20 (Improper Input Validation)

**Issue:**
```c
// src/tpm_common.c:263-271
if (strncmp(line, "max_attempts=", 13) == 0) {
    policy->max_attempts = (uint32_t)atoi(line + 13);  // No validation!
} else if (strncmp(line, "lockout_duration=", 17) == 0) {
    policy->lockout_duration = (uint32_t)atoi(line + 17);  // No validation!
}
```

**Vulnerabilities:**
1. `atoi()` returns 0 on error (same as valid "0")
2. No bounds checking (can set `max_attempts=4294967295`)
3. No validation of reasonable values
4. Negative values wrap to large unsigned values
5. Malformed input silently ignored

**Attack Vectors:**
```bash
# Create malicious policy
echo "max_attempts=999999999999999" > /etc/pinpam/policy
echo "lockout_duration=-1" >> /etc/pinpam/policy
```

**Recommendation:**
```c
char *endptr;
long value = strtol(line + 13, &endptr, 10);

// Validate parsing succeeded
if (endptr == line + 13 || *endptr != '\n') {
    syslog(LOG_ERR, "Invalid policy: malformed max_attempts");
    continue;
}

// Validate range
if (value < 0 || value > 100) {
    syslog(LOG_ERR, "Invalid policy: max_attempts out of range");
    continue;
}

policy->max_attempts = (uint32_t)value;
```

---

## MEDIUM SEVERITY ISSUES

### 8. ⚠️ MEDIUM: Time-Based Side Channel in lockout_check
**Severity:** MEDIUM  
**CWE:** CWE-208 (Observable Timing Discrepancy)

**Issue:**
```c
// src/tpm_common.c:313-325
if (lockout.unlock_time > 0) {
    if (now < (time_t)lockout.unlock_time) {
        // Locked out - detailed error message with time
        fprintf(stderr, "PIN is locked out. Unlocks at %s (%ld seconds remaining)\n", 
                time_str, (long)remaining);
        return 1;
    }
}
```

**Side Channel:**
- Successful vs locked-out attempts have different response times
- Error messages reveal remaining lockout time
- Attacker can enumerate locked accounts by timing

**Recommendation:**
```c
// Generic error message
if (now < (time_t)lockout.unlock_time) {
    syslog(LOG_WARNING, "Lockout active for UID %u", uid);
    sleep(2);  // Rate limit + normalize timing
    return 1;
}
```

---

### 9. ⚠️ MEDIUM: Unvalidated Username Input
**Severity:** MEDIUM  
**CWE:** CWE-20 (Improper Input Validation)

**Issue:**
```c
// src/lib.c:60
const char *username = NULL;
if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL) {
    // ...
}

struct passwd *pwd = getpwnam(username);  // username not validated
```

While PAM provides some validation, username is used in:
1. `getpwnam()` system call
2. Error messages (potential log injection)

**Recommendation:**
```c
// Validate username format
if (!validate_username(username)) {
    syslog(LOG_WARNING, "Invalid username format in PAM auth");
    return PAM_AUTH_ERR;
}
```

---

### 10. ⚠️ MEDIUM: Insufficient Error Handling in NV Operations
**Severity:** MEDIUM  
**CWE:** CWE-755 (Improper Handling of Exceptional Conditions)

**Issue:**
```c
// src/tpm_common.c:107
ESYS_TR nvHandle = ESYS_TR_NONE;
rc = Esys_TR_FromTPMPublic(esys, nv_index, ...);
if (rc != TSS2_RC_SUCCESS) {
    return rc;  // nvHandle leaked?
}
```

Multiple TPM operations can fail, leaving resources in inconsistent state:
- Handles not properly closed on all error paths
- Memory allocations not freed consistently
- TPM context state unclear after failures

**Recommendation:**
- Comprehensive error handling audit
- RAII-style resource management
- Add `__attribute__((cleanup))` for automatic cleanup

---

### 11. ⚠️ MEDIUM: Unbounded PIN Length
**Severity:** MEDIUM  
**CWE:** CWE-120 (Buffer Overflow)

**Issue:**
```c
// src/lib.c:34
strncpy(buf, reply->resp, buf_len-1);
buf[buf_len-1] = '\0';
```

While buffer overflow is prevented, extremely long PINs can:
1. Cause excessive hashing time (DoS)
2. Fill logs with truncated attempts
3. Bypass length validation in setup vs auth

**Recommendation:**
```c
#define PIN_MIN_LEN 4
#define PIN_MAX_LEN 128

// In get_pin_from_user:
size_t pin_len = strlen(reply->resp);
if (pin_len < PIN_MIN_LEN || pin_len >= buf_len) {
    OPENSSL_cleanse(reply->resp, strlen(reply->resp));
    free(reply->resp);
    free(reply);
    return -1;
}
```

---

## LOW SEVERITY / BEST PRACTICES

### 12. ℹ️ LOW: Missing Audit Logging
**Severity:** LOW  
**CWE:** CWE-778 (Insufficient Logging)

**Issue:**
Security events not logged to syslog:
- Failed authentication attempts
- Lockout triggers
- PIN changes
- Administrative operations
- TPM errors

**Recommendation:**
```c
#include <syslog.h>

openlog("pinpam", LOG_PID, LOG_AUTHPRIV);
syslog(LOG_WARNING, "Failed auth for UID %u (attempt %u/%u)", 
       uid, attempts, max_attempts);
```

---

### 13. ℹ️ LOW: Service Configuration File Mismatch
**Severity:** LOW  
**Issue:**

```bash
# service.conf references old PAM arguments
auth required /home/justin/Code/pinpam/libpinpam.so pin_lockout_max_attempts=3 pin_lockout_time=60
```

Code now uses `./policy` file but service.conf has stale arguments.

**Recommendation:**
```bash
# Update service.conf
auth required /home/justin/Code/pinpam/libpinpam.so
```

---

### 14. ℹ️ LOW: Missing Rate Limiting
**Severity:** LOW  
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

**Issue:**
While lockout prevents repeated failures, there's no rate limiting between attempts. Attacker can:
- Try max_attempts very quickly
- Wait for lockout_duration
- Repeat indefinitely

**Recommendation:**
```c
// Add delay on failed attempts
if (ret == PAM_AUTH_ERR) {
    sleep(2 + (lockout_state.failed_attempts * 1));  // Progressive delay
}
```

---

### 15. ℹ️ LOW: No TPM Ownership Verification
**Severity:** LOW  
**Issue:**

Code assumes TPM owner hierarchy is accessible. No verification that:
- TPM is initialized
- Owner password is known/accessible
- Platform is trusted

**Recommendation:**
```c
// Verify TPM state before operations
TSS2_RC verify_tpm_ready(ESYS_CONTEXT *esys) {
    TPMS_CAPABILITY_DATA *capabilityData = NULL;
    TSS2_RC rc = Esys_GetCapability(esys, ...);
    // Verify ownership, check properties
    return rc;
}
```

---

### 16. ℹ️ LOW: Compiler Warnings and Code Quality
**Severity:** LOW  

**Observations:**
```c
// src/lib.c:172 - Possible misleading label
}cleanup_nv:  // Should be on new line: } \n cleanup_nv:

// Missing const correctness in several places
static int get_pin_from_user(pam_handle_t *pamh, char *buf, size_t buf_len)
// buf should not be const (output parameter) ✓

// Some functions could be static
TSS2_RC write_lockout_data(...)  // Only used in tpm_common.c
```

**Recommendation:**
```bash
# Enable strict compiler warnings
cmake -DCMAKE_C_FLAGS="-Wall -Wextra -Werror -Wformat-security"
```

---

## POSITIVE SECURITY FEATURES ✅

The codebase demonstrates several **excellent security practices**:

1. ✅ **Constant-Time Comparison** (`consttime_eq` using `CRYPTO_memcmp`)
2. ✅ **Memory Sanitization** (`OPENSSL_cleanse` used extensively)
3. ✅ **Atomic Lockout Prevention** (TOCTOU fix implemented)
4. ✅ **Integer Overflow Protection** (`validate_uid_safe`)
5. ✅ **No Dictionary Amplification** (TPM provides rate limiting)
6. ✅ **Fail-Closed Design** (errors deny authentication)
7. ✅ **Defense in Depth** (multiple validation layers)

---

## ARCHITECTURE SECURITY CONCERNS

### TPM Security Model
The current design trusts:
- ✅ TPM provides secure storage
- ✅ TPM provides monotonic counters
- ❌ **Assumes owner hierarchy is secure**
- ❌ **No protection against malicious root**

### PAM Integration
- ✅ Properly implements PAM API
- ✅ Handles conversation function correctly
- ⚠️ No integration with PAM's system-auth stack
- ⚠️ Bypasses traditional authentication entirely

---

## COMPLIANCE CONSIDERATIONS

### Standards Alignment
- **NIST SP 800-63B**: ❌ Fails memorized secret requirements (no salt)
- **OWASP ASVS**: ❌ Level 2: Fails credential storage (V2.4)
- **CWE Top 25**: ⚠️ Multiple CWE matches identified
- **PCI DSS**: ❌ 8.2.3: Password storage requirements not met

---

## PRIORITY RECOMMENDATIONS

### Immediate (Before ANY Production Use)
1. **Add salt to hash storage** (Issue #2) - CRITICAL
2. **Fix TPM NV attributes** (Issue #1) - CRITICAL
3. **Use absolute policy path** (Issue #5) - HIGH
4. **Audit all memory sanitization** (Issue #6) - HIGH

### Short Term (Before v1.0 Release)
5. Implement audit logging (Issue #12)
6. Add input validation for policy file (Issue #7)
7. Fix root bypass behavior (Issue #3)
8. Add rate limiting between attempts (Issue #14)

### Long Term (Hardening)
9. Implement TPM policy-based authentication
10. Add SELinux/AppArmor policies
11. Create comprehensive test suite
12. Add fuzzing for input validation

---

## TESTING RECOMMENDATIONS

### Security Test Cases
```bash
# 1. Test lockout enforcement
for i in {1..10}; do echo "wrong" | ./setup_pin & done
# Verify max_attempts enforced atomically

# 2. Test concurrent authentication
pamtester service.conf user authenticate &
pamtester service.conf user authenticate &
# Verify no race conditions

# 3. Test overflow protection
sudo ./setup_pin --clear 65536  # Should fail
sudo ./setup_pin --clear 4294967295  # Should fail

# 4. Test policy injection
cd /tmp && echo "max_attempts=999999" > policy
# Verify PAM doesn't use it

# 5. Test memory sanitization
valgrind --leak-check=full --track-origins=yes ./setup_pin

# 6. Fuzz testing
AFL_HARDEN=1 afl-fuzz -i testcases/ -o findings/ ./setup_pin
```

---

## CONCLUSION

This codebase shows **strong security awareness** with proper fixes for TOCTOU races and integer overflows. However, **critical vulnerabilities remain** that make it unsuitable for production:

### Critical Path to Production:
1. ✅ Fix TOCTOU (DONE)
2. ✅ Fix integer overflow (DONE)
3. ❌ **Add salted hash storage** (MUST FIX)
4. ❌ **Secure TPM NV attributes** (MUST FIX)
5. ❌ **Use absolute policy path** (MUST FIX)

### Estimated Effort:
- **Critical Fixes**: 2-3 days
- **High Priority**: 1 week
- **Comprehensive Hardening**: 2-3 weeks
- **Compliance**: 4-6 weeks

### Risk Assessment:
- **Current State**: ⚠️ HIGH RISK - Not production ready
- **With Critical Fixes**: ⚠️ MEDIUM RISK - Suitable for internal use
- **With All Fixes**: ✅ LOW RISK - Production ready

---

**Security Auditor Signature:**  
_Security Analysis Tool_  
_Date: October 16, 2025_
