
#include "lib.h"
#include "tpm_common.h"
#include <sys/types.h>
#include <pwd.h>
#include <time.h>

// PAM authenticate
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int ret = PAM_AUTH_ERR;
    char *pin = NULL;

    // Open syslog
    openlog("pam_pinpam", LOG_PID, LOG_AUTHPRIV);

    // Get the username from PAM and look up their UID FIRST
    const char *username = NULL;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL) {
        syslog(LOG_ERR, "Failed to get username");
        closelog();
        return PAM_AUTH_ERR;
    }
    
    // Verify user exists before prompting for PIN
    struct passwd *pwd = getpwnam(username);
    if (pwd == NULL) {
        syslog(LOG_ERR, "Failed to get user info for %s", username);
        closelog();
        return PAM_AUTH_ERR;
    }
    
    uid_t uid = pwd->pw_uid;
    
    // Validate UID to prevent integer overflow attacks
    if (validate_uid_safe(uid) != 0) {
        syslog(LOG_ERR, "UID %u is not safe for NV index calculation", uid);
        closelog();
        return PAM_AUTH_ERR;
    }
    
    uint32_t user_nv_index = TPM_NV_INDEX + uid;

    // initialize TPM contexts
    ESYS_CONTEXT *esys_ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    size_t tcti_size = 0;
    TSS2_RC rc = initialize_tpm(&esys_ctx, &tcti_ctx, &tcti_size);
    if (rc != TSS2_RC_SUCCESS || esys_ctx == NULL) {
        syslog(LOG_ERR, "TPM init failed for user %s: 0x%X", username, rc);
        closelog();
        return PAM_AUTH_ERR;
    }

    // Ensure HMAC key exists
    ESYS_TR hmac_key = ESYS_TR_NONE;
    rc = ensure_hmac_key(esys_ctx, &hmac_key);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "Failed to ensure HMAC key for user %s: 0x%X", username, rc);
        cleanup_tpm(&esys_ctx, &tcti_ctx);
        closelog();
        return PAM_AUTH_ERR;
    }

    // Check if user has a PIN configured BEFORE checking lockout or prompting
    // This is a read-only check to see if the NV index exists
    uint8_t *nv_data = NULL;
    size_t nv_size = 0;
    rc = read_nv(esys_ctx, user_nv_index, &nv_data, &nv_size);
    if (rc != TSS2_RC_SUCCESS) {
        // Check if this is a "handle doesn't exist" error (0x18B)
        uint16_t error_code = rc & 0xFFFF;
        if (error_code == 0x018B || error_code == TPM2_RC_HANDLE) {
            // No PIN configured for this user - let other PAM modules handle auth
            syslog(LOG_INFO, "No TPM PIN configured for user %s, skipping TPM authentication", username);
            ret = PAM_AUTHINFO_UNAVAIL;
            goto cleanup;
        }
        // Other errors are real failures
        syslog(LOG_ERR, "Failed to read NV for user %s: 0x%X", username, rc);
        ret = PAM_AUTH_ERR;
        goto cleanup;
    }

    if (nv_size != HMAC_OUTPUT_SIZE) {
        syslog(LOG_ERR, "Unexpected NV size for HMAC for user %s: %zu (expected %d)", username, nv_size, HMAC_OUTPUT_SIZE);
        ret = PAM_AUTH_ERR;
        goto cleanup_nv;
    }

    // Check TPM lockout status BEFORE prompting for PIN
    int lockout_status = check_tpm_lockout_status(esys_ctx);
    if (lockout_status == 1) {
        syslog(LOG_WARNING, "TPM is in lockout mode for user %s", username);
        ret = PAM_AUTH_ERR;
        goto cleanup_nv;
    } else if (lockout_status == -1) {
        syslog(LOG_ERR, "Failed to check TPM lockout status for user %s", username);
        ret = PAM_AUTH_ERR;
        goto cleanup_nv;
    }

    // NOW prompt for PIN after validating user exists, PIN is configured, and TPM is not locked out
    ret = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &pin, "TPM PIN: ");
    if (ret != PAM_SUCCESS || pin == NULL) {
        syslog(LOG_WARNING, "Failed to get PIN from user");
        ret = PAM_AUTH_ERR;
        goto cleanup_nv;
    }
    
    // Log authentication attempt
    syslog(LOG_INFO, "TPM PIN authentication attempt for user %s (UID %u)", username, uid);
    
    // Compute HMAC of the PIN
    unsigned char pin_hmac[HMAC_OUTPUT_SIZE];
    size_t hmac_len = sizeof(pin_hmac);
    rc = tpm_hmac(esys_ctx, hmac_key, (unsigned char*)pin, strlen(pin), pin_hmac, &hmac_len);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "Failed to compute HMAC for user %s: 0x%X", username, rc);
        ret = PAM_AUTH_ERR;
        goto cleanup_nv;
    }

    if (consttime_eq(pin_hmac, nv_data, HMAC_OUTPUT_SIZE)) {
        ret = PAM_SUCCESS;
        // Reset TPM lockout on successful authentication
        // Note: This requires TPM owner authorization and may fail for non-root users (0x921)
        TSS2_RC reset_rc = reset_tpm_lockout(esys_ctx);
        if (reset_rc != TSS2_RC_SUCCESS) {
            // Only log if it's not an authorization failure (which is expected for non-root)
            if ((reset_rc & 0xFFFF) != 0x0921) { // TPM2_RC_AUTHFAIL
                syslog(LOG_WARNING, "Failed to reset TPM lockout after successful auth: 0x%X", reset_rc);
            }
            // Don't fail authentication just because lockout reset failed
        }
        syslog(LOG_INFO, "Successful TPM PIN authentication for user %s (UID %u)", username, uid);
    } else {
        ret = PAM_AUTH_ERR;
        // Failed authentication - TPM's native dictionary attack protection will handle the lockout
        syslog(LOG_WARNING, "Failed TPM PIN authentication for user %s", username);
    }
    // cleanse
    OPENSSL_cleanse(pin_hmac, sizeof(pin_hmac));

cleanup_nv:
    if (nv_data) {
        OPENSSL_cleanse(nv_data, nv_size);
        free(nv_data);
    }

cleanup:
    // Close HMAC key handle
    if (hmac_key != ESYS_TR_NONE) {
        Esys_TR_Close(esys_ctx, &hmac_key);
    }

    // Clean up TPM resources
    cleanup_tpm(&esys_ctx, &tcti_ctx);
    
    // cleanse PIN variable and free memory
    if (pin) {
        OPENSSL_cleanse(pin, strlen(pin));
        free(pin);
    }
    
    closelog();
    return ret;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
