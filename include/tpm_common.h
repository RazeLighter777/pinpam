#ifndef TPM_COMMON_H
#define TPM_COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

// TPM NV index configuration
#define TPM_NV_INDEX 0x01500020U
#define TPM_HMAC_KEY_HANDLE 0x81010001U  // Persistent handle for HMAC key
#define PIN_MIN_LEN 4
#define PIN_MAX_LEN 128
#define HMAC_OUTPUT_SIZE 32  // SHA256 HMAC output size

// Maximum safe UID to prevent integer overflow in NV index calculation
// TPM NV indices are 32-bit, and we use range starting at 0x01500020
// Reserve space up to 0x0150FFFF for user data, giving us ~64K users max
// This prevents collision with reserved TPM NV space (0x01800000+)
#define MAX_SAFE_UID 0x0000FFFFU  // 65535 - maximum safe UID value

// TPM Dictionary Attack Lockout policy configuration
// This configures the TPM's native dictionary attack protection
typedef struct {
    uint32_t max_attempts;      // Maximum failed attempts before lockout (0 = disabled)
    uint32_t lockout_duration;  // Lockout recovery time in seconds
} lockout_policy_t;
// validate pin requirements
const int validate_pin_requirements(const char *pin);
// Initialize TPM context
TSS2_RC initialize_tpm(ESYS_CONTEXT **esys_context, TSS2_TCTI_CONTEXT **tcti_context, size_t* tcti_size);

// Clean up TPM resources
void cleanup_tpm(ESYS_CONTEXT **esys_ctx, TSS2_TCTI_CONTEXT **tcti_ctx);

// Create or load HMAC key in TPM
TSS2_RC ensure_hmac_key(ESYS_CONTEXT *esys, ESYS_TR *key_handle);

// Compute HMAC using TPM
TSS2_RC tpm_hmac(ESYS_CONTEXT *esys, ESYS_TR key_handle, const unsigned char *data, 
                 size_t data_len, unsigned char *out, size_t *out_len);

// Constant-time comparison
int consttime_eq(const void *a, const void *b, size_t n);

// Validate UID to prevent integer overflow in NV index calculation
// Returns: 0 on success, -1 if UID is unsafe
int validate_uid_safe(uid_t uid);

// Read data from TPM NV index
TSS2_RC read_nv(ESYS_CONTEXT *esys, TPM2_HANDLE nv_index, uint8_t **out, size_t *out_size);

// Write data to TPM NV index
TSS2_RC write_nv(ESYS_CONTEXT *esys, TPM2_HANDLE nv_index, const uint8_t *data, size_t data_size);

// TPM Native Dictionary Attack Protection functions

// Read lockout policy from configuration file and apply to TPM
// Returns: 0 on success, -1 on error
int read_lockout_policy(const char *policy_file, lockout_policy_t *policy);

// Configure TPM's native dictionary attack parameters
// Returns: TSS2_RC_SUCCESS on success
TSS2_RC configure_tpm_lockout(ESYS_CONTEXT *esys, const lockout_policy_t *policy);

// Reset TPM dictionary attack lockout (requires lockout auth/owner auth)
// Returns: TSS2_RC_SUCCESS on success
TSS2_RC reset_tpm_lockout(ESYS_CONTEXT *esys);

// Check if TPM is in lockout mode
// Returns: 0 = not locked, 1 = locked, -1 = error
int check_tpm_lockout_status(ESYS_CONTEXT *esys);

#endif // TPM_COMMON_H
