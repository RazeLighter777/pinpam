
#include "lib.h"
#include "tpm_common.h"
#include <sys/types.h>
#include <pwd.h>
#include <time.h>



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

    // Read lockout policy from configuration file
    lockout_policy_t policy;
    read_lockout_policy("./policy", &policy);

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
    
    // Validate UID to prevent integer overflow attacks
    if (validate_uid_safe(uid) != 0) {
        fprintf(stderr, "UID %u is not safe for NV index calculation\n", uid);
        OPENSSL_cleanse(pin, sizeof(pin));
        return PAM_AUTH_ERR;
    }
    
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

    // ATOMIC LOCKOUT: Check and increment attempt counter atomically BEFORE PIN verification
    // This prevents TOCTOU race conditions
    lockout_data_t lockout_state;
    int lockout_status = atomic_lockout_check_and_increment(esys_ctx, user_lockout_index,
                                                            &policy, &lockout_state);
    if (lockout_status != 0) {
        // Either locked out (1) or error (-1) - deny authentication
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
            // Failed attempt already recorded atomically - no need to record again
            if (policy.max_attempts > 0) {
                fprintf(stderr, "Authentication failed (attempt %u/%u)\n", 
                        lockout_state.failed_attempts, policy.max_attempts);
            } else {
                fprintf(stderr, "Authentication failed\n");
            }
        }
        // cleanse
        OPENSSL_cleanse(pin_hash, sizeof(pin_hash));
    } else {
        // plaintext compare (NOT recommended — also do constant-time)
        size_t pin_len = strlen(pin);
        if (pin_len != nv_size) {
            ret = PAM_AUTH_ERR;
            if (policy.max_attempts > 0) {
                fprintf(stderr, "Authentication failed (attempt %u/%u)\n", 
                        lockout_state.failed_attempts, policy.max_attempts);
            } else {
                fprintf(stderr, "Authentication failed\n");
            }
        } else {
            if (consttime_eq(pin, nv_data, nv_size)) {
                ret = PAM_SUCCESS;
                clear_lockout(esys_ctx, user_lockout_index);
            } else {
                ret = PAM_AUTH_ERR;
                if (policy.max_attempts > 0) {
                    fprintf(stderr, "Authentication failed (attempt %u/%u)\n", 
                            lockout_state.failed_attempts, policy.max_attempts);
                } else {
                    fprintf(stderr, "Authentication failed\n");
                }
            }
        }
    }cleanup_nv:
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