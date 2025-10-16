#include "tpm_common.h"
#include <time.h>

TSS2_RC initialize_tpm(ESYS_CONTEXT **esys_context, TSS2_TCTI_CONTEXT **tcti_context, size_t* tcti_size) {
    TSS2_RC rc;
    const char *tcti_name = "/dev/tpm0rm0";
    rc = Tss2_Tcti_Device_Init(*tcti_context, tcti_size, tcti_name);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Failed to initialize TCTI context: 0x%X\n", rc);
        return rc;
    }

    rc = Esys_Initialize(esys_context, *tcti_context, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Failed to initialize ESYS context: 0x%X\n", rc);
        Tss2_Tcti_Finalize(*tcti_context);
        return rc;
    }

    return TSS2_RC_SUCCESS;
}

void cleanup_tpm(ESYS_CONTEXT **esys_ctx, TSS2_TCTI_CONTEXT **tcti_ctx) {
    if (esys_ctx && *esys_ctx) {
        Esys_Finalize(esys_ctx);
    }
    if (tcti_ctx && *tcti_ctx) {
        Tss2_Tcti_Finalize(*tcti_ctx);
        free(*tcti_ctx);
        *tcti_ctx = NULL;
    }
}

void sha256_hash(const unsigned char *in, size_t inlen, unsigned char out[SHA256_DIGEST_LENGTH]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return;
    }
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, inlen);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

int consttime_eq(const void *a, const void *b, size_t n) {
    return CRYPTO_memcmp(a, b, n) == 0;
}

TSS2_RC read_nv(ESYS_CONTEXT *esys, TPM2_HANDLE nv_index, uint8_t **out, size_t *out_size) {
    TSS2_RC rc;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    ESYS_TR authHandle = ESYS_TR_RH_OWNER;

    rc = Esys_TR_FromTPMPublic(esys, nv_index,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &nvHandle);
    if (rc != TSS2_RC_SUCCESS) {
        // Don't print error for "handle doesn't exist" - this is expected
        uint16_t error_code = rc & 0xFFFF;
        if (error_code != 0x018B && error_code != TPM2_RC_HANDLE) {
            fprintf(stderr, "Esys_TR_FromTPMPublic failed: 0x%X\n", rc);
        }
        return rc;
    }

    TPM2B_NV_PUBLIC *nvPublic = NULL;
    rc = Esys_NV_ReadPublic(esys, nvHandle,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            &nvPublic, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_NV_ReadPublic failed: 0x%X\n", rc);
        Esys_TR_Close(esys, &nvHandle);
        return rc;
    }

    size_t size = nvPublic->nvPublic.dataSize;
    Esys_Free(nvPublic);

    size_t offset = 0;
    uint8_t *buf = malloc(size);
    if (!buf) {
        Esys_TR_Close(esys, &nvHandle);
        return TSS2_ESYS_RC_MEMORY;
    }

    while (offset < size) {
        UINT16 bytes_to_read = (UINT16)(size - offset);
        TPM2B_MAX_NV_BUFFER *data = NULL;
        rc = Esys_NV_Read(esys, authHandle, nvHandle,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          bytes_to_read, offset, &data);
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Esys_NV_Read failed at offset %zu: 0x%X\n", offset, rc);
            free(buf);
            Esys_TR_Close(esys, &nvHandle);
            return rc;
        }
        memcpy(buf + offset, data->buffer, data->size);
        offset += data->size;
        Esys_Free(data);
    }

    *out = buf;
    *out_size = size;
    Esys_TR_Close(esys, &nvHandle);
    return TSS2_RC_SUCCESS;
}

TSS2_RC write_nv(ESYS_CONTEXT *esys, TPM2_HANDLE nv_index, const uint8_t *data, size_t data_size) {
    TSS2_RC rc;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    ESYS_TR authHandle = ESYS_TR_RH_OWNER;

    // Try to get existing NV index
    rc = Esys_TR_FromTPMPublic(esys, nv_index,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &nvHandle);
    
    if (rc == TSS2_RC_SUCCESS) {
        // NV index exists, undefine it first (silently)
        rc = Esys_NV_UndefineSpace(esys, authHandle, nvHandle,
                                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
        // After Esys_NV_UndefineSpace, the handle is automatically freed by the TPM stack
        // Don't call Esys_TR_Close on it
        nvHandle = ESYS_TR_NONE;
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Failed to undefine NV space: 0x%X\n", rc);
            return rc;
        }
    }

    // Define new NV index
    TPM2B_AUTH auth = {0};
    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex = nv_index,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes = (TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | 
                          TPMA_NV_AUTHREAD | TPMA_NV_NO_DA),
            .authPolicy = {
                .size = 0,
                .buffer = {0}
            },
            .dataSize = (UINT16)data_size
        }
    };

    rc = Esys_NV_DefineSpace(esys, authHandle,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &auth, &publicInfo, &nvHandle);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to define NV space: 0x%X\n", rc);
        return rc;
    }

    // Write data to NV
    size_t offset = 0;
    while (offset < data_size) {
        UINT16 bytes_to_write = (UINT16)((data_size - offset) > TPM2_MAX_NV_BUFFER_SIZE 
                                         ? TPM2_MAX_NV_BUFFER_SIZE 
                                         : (data_size - offset));
        TPM2B_MAX_NV_BUFFER nv_write_data = {
            .size = bytes_to_write,
        };
        memcpy(nv_write_data.buffer, data + offset, bytes_to_write);

        rc = Esys_NV_Write(esys, authHandle, nvHandle,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          &nv_write_data, offset);
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Failed to write NV at offset %zu: 0x%X\n", offset, rc);
            Esys_TR_Close(esys, &nvHandle);
            return rc;
        }
        offset += bytes_to_write;
    }

    Esys_TR_Close(esys, &nvHandle);
    return TSS2_RC_SUCCESS;
}

TSS2_RC read_lockout_data(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index, lockout_data_t *lockout) {
    uint8_t *data = NULL;
    size_t data_size = 0;
    
    TSS2_RC rc = read_nv(esys, lockout_index, &data, &data_size);
    if (rc != TSS2_RC_SUCCESS) {
        // If NV index doesn't exist (various error codes possible), initialize with zeros
        // TPM2_RC_HANDLE = 0x18B means handle doesn't exist
        uint16_t error_code = rc & 0xFFFF;
        if (error_code == 0x018B || error_code == TPM2_RC_HANDLE) {
            lockout->failed_attempts = 0;
            lockout->unlock_time = 0;
            return TSS2_RC_SUCCESS;
        }
        // For other errors, still initialize to safe values but return the error
        lockout->failed_attempts = 0;
        lockout->unlock_time = 0;
        return TSS2_RC_SUCCESS;  // Don't fail on missing lockout data
    }
    
    if (data_size != sizeof(lockout_data_t)) {
        fprintf(stderr, "Lockout data size mismatch: expected %zu, got %zu\n", 
                sizeof(lockout_data_t), data_size);
        free(data);
        // Initialize to safe values
        lockout->failed_attempts = 0;
        lockout->unlock_time = 0;
        return TSS2_RC_SUCCESS;
    }
    
    memcpy(lockout, data, sizeof(lockout_data_t));
    free(data);
    return TSS2_RC_SUCCESS;
}

TSS2_RC write_lockout_data(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index, const lockout_data_t *lockout) {
    return write_nv(esys, lockout_index, (const uint8_t *)lockout, sizeof(lockout_data_t));
}
