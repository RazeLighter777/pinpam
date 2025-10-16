
#include "lib.h"
#include "tpm_common.h"
#include <sys/types.h>
#include <pwd.h>
#include <time.h>

// Parse module arguments for lockout configuration
static void parse_lockout_args(int argc, const char **argv, 
                                uint32_t *max_attempts, uint32_t *lockout_time) {
    *max_attempts = 0;
    *lockout_time = 0;
    
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "pin_lockout_max_attempts=", 25) == 0) {
            *max_attempts = (uint32_t)atoi(argv[i] + 25);
        } else if (strncmp(argv[i], "pin_lockout_time=", 17) == 0) {
            *lockout_time = (uint32_t)atoi(argv[i] + 17);
        }
    }
}

// Check if PIN is currently locked out
static int check_lockout(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index,
                         uint32_t max_attempts, uint32_t lockout_time) {
    if (max_attempts == 0) {
        return 0; // Lockout disabled
    }
    
    lockout_data_t lockout;
    TSS2_RC rc = read_lockout_data(esys, lockout_index, &lockout);
    // read_lockout_data now always succeeds, initializing to zeros if not found
    
    // Check if permanently locked (lockout_time == 0 and attempts exceeded)
    if (lockout_time == 0 && lockout.failed_attempts >= max_attempts) {
        fprintf(stderr, "PIN is permanently locked out\n");
        return 1; // Locked out permanently
    }
    
    // Check if temporarily locked
    if (lockout.unlock_time > 0) {
        time_t now = time(NULL);
        if (now < (time_t)lockout.unlock_time) {
            time_t unlock_at = (time_t)lockout.unlock_time;
            time_t remaining = unlock_at - now;
            char time_str[64];
            struct tm *tm_info = localtime(&unlock_at);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            
            fprintf(stderr, "PIN is locked out. Unlocks at %s (%ld seconds remaining)\n", 
                    time_str, (long)remaining);
            return 1; // Still locked
        } else {
            // Lock expired, reset the lockout
            lockout.failed_attempts = 0;
            lockout.unlock_time = 0;
            write_lockout_data(esys, lockout_index, &lockout);
        }
    }
    
    return 0; // Not locked out
}

// Update lockout data after failed authentication
static void record_failed_attempt(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index,
                                   uint32_t max_attempts, uint32_t lockout_time) {
    if (max_attempts == 0) {
        return; // Lockout disabled
    }
    
    lockout_data_t lockout;
    TSS2_RC rc = read_lockout_data(esys, lockout_index, &lockout);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to read lockout data: 0x%X\n", rc);
        return;
    }
    
    lockout.failed_attempts++;
    
    if (lockout.failed_attempts >= max_attempts) {
        if (lockout_time > 0) {
            // Temporary lockout
            time_t now = time(NULL);
            time_t unlock_at = now + lockout_time;
            lockout.unlock_time = (uint64_t)unlock_at;
            
            char time_str[64];
            struct tm *tm_info = localtime(&unlock_at);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            
            fprintf(stderr, "PIN locked out until %s (attempt %u/%u)\n", 
                    time_str, lockout.failed_attempts, max_attempts);
        } else {
            // Permanent lockout
            lockout.unlock_time = 0;
            fprintf(stderr, "PIN permanently locked out (attempt %u/%u)\n",
                    lockout.failed_attempts, max_attempts);
        }
    } else {
        fprintf(stderr, "Failed attempt %u/%u\n", lockout.failed_attempts, max_attempts);
    }
    
    rc = write_lockout_data(esys, lockout_index, &lockout);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to write lockout data: 0x%X\n", rc);
    }
}

// Clear lockout data after successful authentication
static void clear_lockout(ESYS_CONTEXT *esys, TPM2_HANDLE lockout_index) {
    lockout_data_t lockout = {0};
    TSS2_RC rc = write_lockout_data(esys, lockout_index, &lockout);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to clear lockout data: 0x%X\n", rc);
    }
}

// Helper: get the PIN typed by the user via PAM
static int get_pin_from_user(pam_handle_t *pamh, char *buf, size_t buf_len) {
    const char *resp = NULL;
    struct pam_message msg = {
        .msg_style = PAM_PROMPT_ECHO_OFF,
        .msg = "TPM PIN: "
    };
    const struct pam_message *msgp = &msg;
    struct pam_response *reply = NULL;
    struct pam_conv *conv;
    int r = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
    if (r != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
        return -1;
    }
    r = conv->conv(1, &msgp, &reply, conv->appdata_ptr);
    if (r != PAM_SUCCESS || reply == NULL) {
        if (reply) {
            if (reply->resp) { free(reply->resp); }
            free(reply);
        }
        return -1;
    }
    if (reply->resp == NULL) {
        free(reply);
        return -1;
    }
    // copy safely
    strncpy(buf, reply->resp, buf_len-1);
    buf[buf_len-1] = '\0';
    // wipe and free PAM's response memory
    OPENSSL_cleanse(reply->resp, strlen(reply->resp));
    free(reply->resp);
    free(reply);
    return 0;
}

// PAM authenticate
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int ret = PAM_AUTH_ERR;
    char pin[PIN_MAX_LEN];

    // Parse lockout configuration from module arguments
    uint32_t pin_lockout_max_attempts = 0;
    uint32_t pin_lockout_time = 0;
    parse_lockout_args(argc, argv, &pin_lockout_max_attempts, &pin_lockout_time);

    if (get_pin_from_user(pamh, pin, sizeof(pin)) != 0) {
        return PAM_AUTH_ERR;
    }

    // Get the username from PAM and look up their UID
    const char *username = NULL;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL) {
        fprintf(stderr, "Failed to get username\n");
        OPENSSL_cleanse(pin, sizeof(pin));
        return PAM_AUTH_ERR;
    }
    
    struct passwd *pwd = getpwnam(username);
    if (pwd == NULL) {
        fprintf(stderr, "Failed to get user info for %s\n", username);
        OPENSSL_cleanse(pin, sizeof(pin));
        return PAM_AUTH_ERR;
    }
    
    uid_t uid = pwd->pw_uid;
    uint32_t user_nv_index = TPM_NV_INDEX + uid;
    uint32_t user_lockout_index = TPM_NV_LOCKOUT_BASE + uid;

    // initialize TPM contexts
    ESYS_CONTEXT *esys_ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    size_t tcti_size = 0;
    TSS2_RC rc = initialize_tpm(&esys_ctx, &tcti_ctx, &tcti_size);
    if (rc != TSS2_RC_SUCCESS || esys_ctx == NULL) {
        fprintf(stderr, "TPM init failed: 0x%X\n", rc);
        OPENSSL_cleanse(pin, sizeof(pin));
        return PAM_AUTH_ERR;
    }

    // Check if PIN is currently locked out
    int lockout_status = check_lockout(esys_ctx, user_lockout_index, 
                                       pin_lockout_max_attempts, pin_lockout_time);
    if (lockout_status > 0) {
        // PIN is locked out
        ret = PAM_AUTH_ERR;
        goto cleanup;
    }

    // Read NV index
    uint8_t *nv_data = NULL;
    size_t nv_size = 0;
    rc = read_nv(esys_ctx, user_nv_index, &nv_data, &nv_size);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to read NV: 0x%X\n", rc);
        ret = PAM_AUTH_ERR;
        goto cleanup;
    }

    // Choose mode:
    // A) If NV contains plaintext PIN (NOT recommended) -> compare directly
    // B) Recommended: NV contains SHA-256 of PIN (32 bytes) -> hash user PIN and compare
    const int use_hash = 1; // set to 0 if NV contains plaintext (not recommended)

    if (use_hash) {
        if (nv_size != SHA256_DIGEST_LENGTH) {
            fprintf(stderr, "Unexpected NV size for hash: %zu\n", nv_size);
            ret = PAM_AUTH_ERR;
            goto cleanup_nv;
        }
        unsigned char pin_hash[SHA256_DIGEST_LENGTH];
        sha256_hash((unsigned char*)pin, strlen(pin), pin_hash);

        if (consttime_eq(pin_hash, nv_data, SHA256_DIGEST_LENGTH)) {
            ret = PAM_SUCCESS;
            // Clear lockout on successful authentication
            clear_lockout(esys_ctx, user_lockout_index);
        } else {
            ret = PAM_AUTH_ERR;
            // Record failed attempt
            record_failed_attempt(esys_ctx, user_lockout_index, 
                                  pin_lockout_max_attempts, pin_lockout_time);
        }
        // cleanse
        OPENSSL_cleanse(pin_hash, sizeof(pin_hash));
    } else {
        // plaintext compare (NOT recommended — also do constant-time)
        size_t pin_len = strlen(pin);
        if (pin_len != nv_size) {
            ret = PAM_AUTH_ERR;
            record_failed_attempt(esys_ctx, user_lockout_index,
                                  pin_lockout_max_attempts, pin_lockout_time);
        } else {
            if (consttime_eq(pin, nv_data, nv_size)) {
                ret = PAM_SUCCESS;
                clear_lockout(esys_ctx, user_lockout_index);
            } else {
                ret = PAM_AUTH_ERR;
                record_failed_attempt(esys_ctx, user_lockout_index,
                                      pin_lockout_max_attempts, pin_lockout_time);
            }
        }
    }

cleanup_nv:
    if (nv_data) {
        OPENSSL_cleanse(nv_data, nv_size);
        free(nv_data);
    }

cleanup:

    // Clean up TPM resources
    cleanup_tpm(&esys_ctx, &tcti_ctx);
    
    // cleanse PIN variable
    OPENSSL_cleanse(pin, sizeof(pin));
    return ret;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}