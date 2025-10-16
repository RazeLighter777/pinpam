#ifndef TPM_COMMON_H
#define TPM_COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

// TPM NV index configuration
#define TPM_NV_INDEX 0x01500020U
#define TPM_NV_LOCKOUT_BASE 0x01500100U
#define PIN_MAX_LEN 128

// Maximum safe UID to prevent integer overflow in NV index calculation
// TPM NV indices are 32-bit, and we use ranges starting at 0x01500020 and 0x01500100
// Reserve space up to 0x0150FFFF for user data, giving us ~64K users max
// This prevents collision with reserved TPM NV space (0x01800000+)
#define MAX_SAFE_UID 0x0000FFFFU  // 65535 - maximum safe UID value

// Lockout policy configuration
typedef struct {
    uint32_t max_attempts;      // Maximum failed attempts before lockout (0 = disabled)
    uint32_t lockout_duration;  // Lockout duration in seconds (0 = permanent)
} lockout_policy_t;

// Lockout data structure stored in TPM
typedef struct {
    uint32_t failed_attempts;
    uint64_t unlock_time;  // Unix timestamp when PIN becomes unlocked (0 if not locked)
} lockout_data_t;

// Initialize TPM context
TSS2_RC initialize_tpm(ESYS_CONTEXT **esys_context, TSS2_TCTI_CONTEXT **tcti_context, size_t* tcti_size);

// Clean up TPM resources
void cleanup_tpm(ESYS_CONTEXT **esys_ctx, TSS2_TCTI_CONTEXT **tcti_ctx);

// Compute SHA-256 hash
void sha256_hash(const unsigned char *in, size_t inlen, unsigned char out[SHA256_DIGEST_LENGTH]);

// Constant-time comparison
int consttime_eq(const void *a, const void *b, size_t n);

// Validate UID to prevent integer overflow in NV index calculation
// Returns: 0 on success, -1 if UID is unsafe
int validate_uid_safe(uid_t uid);

// Read data from TPM NV index
TSS2_RC read_nv(ESYS_CONTEXT *esys, TPM2_HANDLE nv_index, uint8_t **out, size_t *out_size);

// Write data to TPM NV index
TSS2_RC write_nv(ESYS_CONTEXT *esys, TPM2_HANDLE nv_index, const uint8_t *data, size_t data_size);

// Lockout management functions
TSS2_RC read_lockout_data(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index, lockout_data_t *lockout);
TSS2_RC write_lockout_data(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index, const lockout_data_t *lockout);

// Read lockout policy from configuration file
// Returns: 0 on success, -1 on error
int read_lockout_policy(const char *policy_file, lockout_policy_t *policy);

// Atomically check lockout and increment counter (TOCTOU-safe)
// Returns: 0 = proceed, 1 = locked out, -1 = error
int atomic_lockout_check_and_increment(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index,
                                       const lockout_policy_t *policy, lockout_data_t *out_lockout);

// Clear lockout data after successful operation
TSS2_RC clear_lockout(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index);

#endif // TPM_COMMON_H
