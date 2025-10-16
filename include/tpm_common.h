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

// Read data from TPM NV index
TSS2_RC read_nv(ESYS_CONTEXT *esys, TPM2_HANDLE nv_index, uint8_t **out, size_t *out_size);

// Write data to TPM NV index
TSS2_RC write_nv(ESYS_CONTEXT *esys, TPM2_HANDLE nv_index, const uint8_t *data, size_t data_size);

// Lockout management functions
TSS2_RC read_lockout_data(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index, lockout_data_t *lockout);
TSS2_RC write_lockout_data(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index, const lockout_data_t *lockout);

#endif // TPM_COMMON_H
