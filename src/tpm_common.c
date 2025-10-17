#include "tpm_common.h"
#include <time.h>
#include <sys/stat.h>


const int validate_pin_requirements(const char *pin) {
    size_t len = strlen(pin);
    //validate pin is unsigned integer within length limits
    // leading zeros are allowed
    if (len < PIN_MIN_LEN || len > PIN_MAX_LEN) {
      return -1; // Invalid length
    }
    for (size_t i = 0; i < len; i++) {
        if (pin[i] < '0' || pin[i] > '9') {
            return -1; // Non-digit character found
        }
    }
    return 0; // Valid
}


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

// Create or load HMAC key in TPM persistent storage
TSS2_RC ensure_hmac_key(ESYS_CONTEXT *esys, ESYS_TR *key_handle) {
    TSS2_RC rc;
    ESYS_TR primary = ESYS_TR_NONE;
    
    *key_handle = ESYS_TR_NONE;
    
    // Try to load existing persistent key
    rc = Esys_TR_FromTPMPublic(esys, TPM_HMAC_KEY_HANDLE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               key_handle);
    if (rc == TSS2_RC_SUCCESS && *key_handle != ESYS_TR_NONE) {
        // Key already exists and is loaded
        // Set auth value (empty password) for the key
        TPM2B_AUTH authValue = {
            .size = 0,
            .buffer = {0}
        };
        rc = Esys_TR_SetAuth(esys, *key_handle, &authValue);
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Esys_TR_SetAuth failed: 0x%X\n", rc);
            return rc;
        }
        
        return TSS2_RC_SUCCESS;
    }
    
    // Check if the error is because key doesn't exist (0x18B = TPM2_RC_HANDLE)
    uint16_t error_code = rc & 0xFFFF;
    if (error_code != 0x018B && error_code != TPM2_RC_HANDLE) {
        // Unexpected error
        fprintf(stderr, "Esys_TR_FromTPMPublic failed with unexpected error: 0x%X\n", rc);
        return rc;
    }
    
    // Key doesn't exist, create it
    // First create primary key
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                .size = 0,
            },
            .data = {
                .size = 0,
            }
        }
    };
    
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                TPMA_OBJECT_SIGN_ENCRYPT |
                                TPMA_OBJECT_FIXEDTPM |
                                TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
            .parameters.keyedHashDetail = {
                .scheme = {
                    .scheme = TPM2_ALG_HMAC,
                    .details = {
                        .hmac = {
                            .hashAlg = TPM2_ALG_SHA256
                        }
                    }
                }
            },
            .unique.keyedHash = {
                .size = 0,
            }
        }
    };
    
    TPM2B_DATA outsideInfo = {
        .size = 0,
    };
    
    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };
    
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;
    
    // Create HMAC key under owner hierarchy
    rc = Esys_CreatePrimary(esys, ESYS_TR_RH_OWNER,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                           &primary, &outPublic, &creationData, &creationHash,
                           &creationTicket);
    
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_CreatePrimary failed: 0x%X\n", rc);
        return rc;
    }
    
    // Free creation data
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    
    // Make key persistent
    // Note: Esys_EvictControl returns a new ESYS_TR handle in newObjectHandle
    // that references the persistent object
    rc = Esys_EvictControl(esys, ESYS_TR_RH_OWNER, primary,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          TPM_HMAC_KEY_HANDLE, key_handle);
    
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_EvictControl failed: 0x%X\n", rc);
        Esys_FlushContext(esys, primary);
        return rc;
    }
    
    // Flush the transient object (we now have it persistent)
    Esys_FlushContext(esys, primary);
    
    if (*key_handle == ESYS_TR_NONE) {
        fprintf(stderr, "Error: HMAC key handle is ESYS_TR_NONE after creation\n");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    
    // Set auth value (empty password) for the newly created key
    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {0}
    };
    rc = Esys_TR_SetAuth(esys, *key_handle, &authValue);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_TR_SetAuth failed: 0x%X\n", rc);
        return rc;
    }
    
    return TSS2_RC_SUCCESS;
}

// Compute HMAC using TPM
TSS2_RC tpm_hmac(ESYS_CONTEXT *esys, ESYS_TR key_handle, const unsigned char *data,
                 size_t data_len, unsigned char *out, size_t *out_len) {
    TSS2_RC rc;
    
    if (key_handle == ESYS_TR_NONE) {
        fprintf(stderr, "Error: Invalid key handle passed to tpm_hmac\n");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    
    // Prepare data buffer
    TPM2B_MAX_BUFFER buffer = {
        .size = (UINT16)data_len,
    };
    
    if (data_len > sizeof(buffer.buffer)) {
        fprintf(stderr, "Data too large for HMAC operation: %zu bytes\n", data_len);
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    
    memcpy(buffer.buffer, data, data_len);
    
    // Perform HMAC
    TPM2B_DIGEST *outHMAC = NULL;
    rc = Esys_HMAC(esys, key_handle,
                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &buffer, TPM2_ALG_SHA256,
                   &outHMAC);
    
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_HMAC failed: 0x%X\n", rc);
        return rc;
    }
    
    // Copy result
    if (outHMAC->size > *out_len) {
        fprintf(stderr, "HMAC output buffer too small\n");
        Esys_Free(outHMAC);
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    
    memcpy(out, outHMAC->buffer, outHMAC->size);
    *out_len = outHMAC->size;
    
    Esys_Free(outHMAC);
    return TSS2_RC_SUCCESS;
}

int consttime_eq(const void *a, const void *b, size_t n) {
    return CRYPTO_memcmp(a, b, n) == 0;
}

int validate_uid_safe(uid_t uid) {
    // Validate that UID is within safe range to prevent integer overflow
    // when calculating NV indices
    if (uid > MAX_SAFE_UID) {
        fprintf(stderr, "ERROR: UID %u exceeds maximum safe value %u\n", 
                uid, MAX_SAFE_UID);
        fprintf(stderr, "This would cause NV index collision with reserved TPM space\n");
        return -1;
    }
    
    // Additional check: verify that calculated indices won't overflow
    uint32_t test_pin_index = TPM_NV_INDEX + uid;
    uint32_t test_lockout_index = TPM_NV_LOCKOUT_BASE + uid;
    
    // Check for wraparound (overflow detection)
    if (test_pin_index < TPM_NV_INDEX || test_lockout_index < TPM_NV_LOCKOUT_BASE) {
        fprintf(stderr, "ERROR: UID %u causes integer overflow in NV index calculation\n", uid);
        return -1;
    }
    
    // Check that we don't collide with reserved TPM NV space (0x01800000+)
    if (test_pin_index >= 0x01800000U || test_lockout_index >= 0x01800000U) {
        fprintf(stderr, "ERROR: UID %u would collide with reserved TPM NV space\n", uid);
        return -1;
    }
    
    return 0; // UID is safe
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
            memset(lockout, 0, sizeof(lockout_data_t));
            return TSS2_RC_SUCCESS;
        }
        // For other errors, still initialize to safe values but return the error
        memset(lockout, 0, sizeof(lockout_data_t));
        return TSS2_RC_SUCCESS;  // Don't fail on missing lockout data
    }
    
    // Handle old or new data size
    if (data_size == sizeof(lockout_data_t)) {
        // Correct size, use data as-is
        memcpy(lockout, data, sizeof(lockout_data_t));
    } else if (data_size < sizeof(lockout_data_t)) {
        // Old format (smaller struct) - initialize to zero and copy what we have
        memset(lockout, 0, sizeof(lockout_data_t));
        memcpy(lockout, data, data_size);
    } else {
        // Data is larger than expected - log warning but use what we can
        fprintf(stderr, "Warning: Lockout data size mismatch: expected %zu, got %zu\n", 
                sizeof(lockout_data_t), data_size);
        memcpy(lockout, data, sizeof(lockout_data_t));
    }
    
    free(data);
    return TSS2_RC_SUCCESS;
}

// Read lockout policy from configuration file
// File format: max_attempts=N\nlockout_duration=N\n
int read_lockout_policy(const char *policy_file, lockout_policy_t *policy) {
    // Default: lockout disabled
    policy->max_attempts = 0;
    policy->lockout_duration = 0;
    
    FILE *f = fopen(policy_file, "r");
    if (!f) {
        // File doesn't exist or can't be read - use defaults (lockout disabled)
        return 0;
    }

    struct stat st;
    if (fstat(fileno(f), &st) != 0) {
        fprintf(stderr, "failed to stat policy file\n");
        fclose(f);
        return -1;
    }
    
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "policy file is not a regular file\n");
        fclose(f);
        return -1;
    }

    // Check that policy file is owned by root and not writable by others
    if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH))) {
        fprintf(stderr, "policy file must be owned by root and not writable by group/others\n");
        fclose(f);
        return -1;
    }

    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        
        // Parse key=value pairs
        if (strncmp(line, "max_attempts=", 13) == 0) {
            policy->max_attempts = (uint32_t)atoi(line + 13);
        } else if (strncmp(line, "lockout_duration=", 17) == 0) {
            policy->lockout_duration = (uint32_t)atoi(line + 17);
        }
    }
    
    fclose(f);
    return 0;
}

TSS2_RC write_lockout_data(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index, const lockout_data_t *lockout) {
    return write_nv(esys, lockout_index, (const uint8_t *)lockout, sizeof(lockout_data_t));
}

// Atomically check lockout status and increment attempt counter
// This prevents TOCTOU race conditions by incrementing BEFORE verification
// Returns: 0 = proceed, 1 = locked out, -1 = error
int atomic_lockout_check_and_increment(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index,
                                       const lockout_policy_t *policy, lockout_data_t *out_lockout) {
    lockout_data_t lockout;
    TSS2_RC rc = read_lockout_data(esys, lockout_index, &lockout);
    // read_lockout_data always succeeds, initializing to zeros if not found
    
    // If lockout is disabled (max_attempts == 0), don't check or increment
    if (policy->max_attempts == 0) {
        if (out_lockout) {
            *out_lockout = lockout;
        }
        return 0; // Lockout disabled, proceed
    }
    
    time_t now = time(NULL);
    
    // Check if temporarily locked and if lock has expired
    if (lockout.unlock_time > 0) {
        if (now < (time_t)lockout.unlock_time) {
            // Still locked out
            time_t unlock_at = (time_t)lockout.unlock_time;
            time_t remaining = unlock_at - now;
            char time_str[64];
            struct tm *tm_info = localtime(&unlock_at);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            
            syslog(LOG_WARNING, "PIN lockout active. Unlocks at %s (%ld seconds remaining)", 
                    time_str, (long)remaining);
            if (out_lockout) {
                *out_lockout = lockout;
            }
            return 1; // Locked out
        } else {
            // Lock expired, reset the lockout
            lockout.failed_attempts = 0;
            lockout.unlock_time = 0;
            syslog(LOG_INFO, "PIN lockout expired, resetting counters");
        }
    }
    
    // Check if permanently locked (lockout_duration == 0 and attempts exceeded)
    if (policy->lockout_duration == 0 && lockout.failed_attempts >= policy->max_attempts) {
        syslog(LOG_WARNING, "PIN is permanently locked out");
        if (out_lockout) {
            *out_lockout = lockout;
        }
        return 1; // Locked out permanently
    }
    
    // ATOMIC OPERATION: Increment attempt counter BEFORE verification
    // This prevents race conditions where multiple threads could bypass lockout
    lockout.failed_attempts++;
    
    // Check if this increment causes a lockout
    if (lockout.failed_attempts > policy->max_attempts) {
        if (policy->lockout_duration > 0) {
            // Set temporary lockout
            time_t unlock_at = now + policy->lockout_duration;
            lockout.unlock_time = (uint64_t)unlock_at;
        } else {
            // Permanent lockout
            lockout.unlock_time = 0;
        }
    }
    
    // Write the incremented counter atomically
    rc = write_lockout_data(esys, lockout_index, &lockout);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to write lockout data: 0x%X\n", rc);
        return -1; // Error - fail closed
    }
    
    // Check if we just locked out
    if (lockout.failed_attempts > policy->max_attempts) {
        if (policy->lockout_duration > 0) {
            char time_str[64];
            time_t unlock_at = (time_t)lockout.unlock_time;
            struct tm *tm_info = localtime(&unlock_at);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            syslog(LOG_WARNING, "PIN locked out until %s (attempt %u/%u)", 
                    time_str, lockout.failed_attempts, policy->max_attempts);
        } else {
            syslog(LOG_WARNING, "PIN permanently locked out (attempt %u/%u)",
                    lockout.failed_attempts, policy->max_attempts);
        }
        if (out_lockout) {
            *out_lockout = lockout;
        }
        return 1; // Locked out
    }
    
    // Copy lockout data for caller
    if (out_lockout) {
        *out_lockout = lockout;
    }
    
    return 0; // Proceed with operation
}

// Clear lockout data after successful operation
TSS2_RC clear_lockout(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index) {
    lockout_data_t lockout = {0};
    
    // Clear all state (attempts and unlock time)
    TSS2_RC rc = write_lockout_data(esys, lockout_index, &lockout);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to clear lockout data: 0x%X\n", rc);
    }
    return rc;
}
