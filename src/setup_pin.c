#include "tpm_common.h"
#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <getopt.h>
#include <time.h>

static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("\nOptions:\n");
    printf("  --unlock <uid>    Unlock the PIN for the specified UID (requires root)\n");
    printf("  --clear <uid>     Delete PIN and lockout data for the specified UID (requires root)\n");
    printf("  -h, --help        Display this help message\n");
    printf("\nDefault behavior (no options):\n");
    printf("  Set or change PIN for current user\n");
    printf("  - If running as root: can change any user's PIN\n");
    printf("  - If running as regular user: must enter current PIN to change\n");
}

// Verify current PIN before allowing change
static int verify_current_pin(ESYS_CONTEXT *esys, ESYS_TR hmac_key, uint32_t user_nv_index, const char *pin) {
    uint8_t *nv_data = NULL;
    size_t nv_size = 0;
    
    TSS2_RC rc = read_nv(esys, user_nv_index, &nv_data, &nv_size);
    if (rc != TSS2_RC_SUCCESS) {
        // If NV index doesn't exist, this is the first PIN setup
        if ((rc & 0xFFFF) == TPM2_RC_HANDLE) {
            return 1; // Allow setup
        }
        fprintf(stderr, "Failed to read existing PIN: 0x%X\n", rc);
        return 0;
    }
    
    if (nv_size != HMAC_OUTPUT_SIZE) {
        fprintf(stderr, "Unexpected PIN data size: %zu (expected %d)\n", nv_size, HMAC_OUTPUT_SIZE);
        free(nv_data);
        return 0;
    }
    
    unsigned char pin_hmac[HMAC_OUTPUT_SIZE];
    size_t hmac_len = sizeof(pin_hmac);
    rc = tpm_hmac(esys, hmac_key, (unsigned char*)pin, strlen(pin), pin_hmac, &hmac_len);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to compute HMAC: 0x%X\n", rc);
        free(nv_data);
        return 0;
    }
    
    int valid = consttime_eq(pin_hmac, nv_data, HMAC_OUTPUT_SIZE);
    
    OPENSSL_cleanse(pin_hmac, sizeof(pin_hmac));
    OPENSSL_cleanse(nv_data, nv_size);
    free(nv_data);
    
    return valid;
}

// Delete NV index
static TSS2_RC delete_nv(ESYS_CONTEXT *esys, TPM2_HANDLE nv_index) {
    TSS2_RC rc;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    ESYS_TR authHandle = ESYS_TR_RH_OWNER;

    rc = Esys_TR_FromTPMPublic(esys, nv_index,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &nvHandle);
    
    if (rc != TSS2_RC_SUCCESS) {
        // NV index doesn't exist - check for handle error (0x18B)
        uint16_t error_code = rc & 0xFFFF;
        if (error_code == 0x018B || error_code == TPM2_RC_HANDLE) {
            // Index doesn't exist, nothing to delete - this is fine
            return TSS2_RC_SUCCESS;
        }
        // Only print error for unexpected failures
        fprintf(stderr, "Failed to get NV handle: 0x%X\n", rc);
        return rc;
    }

    rc = Esys_NV_UndefineSpace(esys, authHandle, nvHandle,
                               ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    
    // Close the handle before checking rc
    if (nvHandle != ESYS_TR_NONE) {
        Esys_TR_Close(esys, &nvHandle);
    }
    
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to undefine NV space: 0x%X\n", rc);
    }
    
    return rc;
}

// Read PIN from stdin without echoing
static int read_pin_from_stdin(const char *prompt, char *buf, size_t buf_len) {
    struct termios old_term, new_term;
    
    printf("%s", prompt);
    fflush(stdout);
    
    // Disable echo
    if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
        return -1;
    }
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term) != 0) {
        return -1;
    }
    
    // Read PIN
    if (fgets(buf, buf_len, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
        return -1;
    }
    
    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
    printf("\n");
    
    // Remove trailing newline
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') {
        buf[len-1] = '\0';
    }
    
    return 0;
}

int main(int argc, char **argv) {
    char pin[PIN_MAX_LEN];
    char pin_confirm[PIN_MAX_LEN];
    int ret = 1;
    int unlock_mode = 0;
    int clear_mode = 0;
    uid_t target_uid = 0;
    uid_t current_uid = getuid();
    uid_t effective_uid = geteuid();
    int is_root = (effective_uid == 0);
    
    // Open syslog
    openlog("setup_pin", LOG_PID, LOG_AUTHPRIV);
    
    // Parse command line arguments
    static struct option long_options[] = {
        {"unlock", required_argument, 0, 'u'},
        {"clear", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'u':
                unlock_mode = 1;
                target_uid = (uid_t)atoi(optarg);
                break;
            case 'c':
                clear_mode = 1;
                target_uid = (uid_t)atoi(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Initialize TPM
    ESYS_CONTEXT *esys_ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    size_t tcti_size = 0;
    
    TSS2_RC rc = initialize_tpm(&esys_ctx, &tcti_ctx, &tcti_size);
    if (rc != TSS2_RC_SUCCESS || esys_ctx == NULL) {
        fprintf(stderr, "TPM init failed: 0x%X\n", rc);
        fprintf(stderr, "Make sure you have access to /dev/tpm0rm0 (may need sudo)\n");
        return 1;
    }
    
    // Ensure HMAC key exists
    ESYS_TR hmac_key = ESYS_TR_NONE;
    rc = ensure_hmac_key(esys_ctx, &hmac_key);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to ensure HMAC key: 0x%X\n", rc);
        cleanup_tpm(&esys_ctx, &tcti_ctx);
        return 1;
    }
    
    // Handle unlock mode
    if (unlock_mode) {
        if (!is_root) {
            fprintf(stderr, "Error: --unlock requires root privileges\n");
            if (hmac_key != ESYS_TR_NONE) {
                Esys_TR_Close(esys_ctx, &hmac_key);
            }
            cleanup_tpm(&esys_ctx, &tcti_ctx);
            return 1;
        }
        
        // Validate target UID to prevent integer overflow attacks
        if (validate_uid_safe(target_uid) != 0) {
            fprintf(stderr, "UID %u is not safe for NV index calculation\n", target_uid);
            if (hmac_key != ESYS_TR_NONE) {
                Esys_TR_Close(esys_ctx, &hmac_key);
            }
            cleanup_tpm(&esys_ctx, &tcti_ctx);
            return 1;
        }
        
        uint32_t user_lockout_index = TPM_NV_LOCKOUT_BASE + target_uid;
        
        printf("TPM PIN Unlock Utility\n");
        printf("======================\n");
        printf("Unlocking PIN for UID %d\n", target_uid);
        
        lockout_data_t lockout = {0};
        rc = write_lockout_data(esys_ctx, user_lockout_index, &lockout);
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Failed to clear lockout data: 0x%X\n", rc);
            syslog(LOG_ERR, "Failed to unlock PIN for UID %u by UID %u", target_uid, current_uid);
            ret = 1;
        } else {
            printf("✓ PIN lockout cleared for UID %d\n", target_uid);
            syslog(LOG_NOTICE, "PIN unlocked for UID %u by UID %u", target_uid, current_uid);
            ret = 0;
        }
        
        if (hmac_key != ESYS_TR_NONE) {
            Esys_TR_Close(esys_ctx, &hmac_key);
        }
        cleanup_tpm(&esys_ctx, &tcti_ctx);
        closelog();
        return ret;
    }
    
    // Handle clear mode
    if (clear_mode) {
        if (!is_root) {
            fprintf(stderr, "Error: --clear requires root privileges\n");
            if (hmac_key != ESYS_TR_NONE) {
                Esys_TR_Close(esys_ctx, &hmac_key);
            }
            cleanup_tpm(&esys_ctx, &tcti_ctx);
            return 1;
        }
        
        // Validate target UID to prevent integer overflow attacks
        if (validate_uid_safe(target_uid) != 0) {
            fprintf(stderr, "UID %u is not safe for NV index calculation\n", target_uid);
            if (hmac_key != ESYS_TR_NONE) {
                Esys_TR_Close(esys_ctx, &hmac_key);
            }
            cleanup_tpm(&esys_ctx, &tcti_ctx);
            return 1;
        }
        
        uint32_t user_nv_index = TPM_NV_INDEX + target_uid;
        uint32_t user_lockout_index = TPM_NV_LOCKOUT_BASE + target_uid;
        
        printf("TPM PIN Clear Utility\n");
        printf("=====================\n");
        printf("Clearing PIN and lockout data for UID %d\n", target_uid);
        
        // Delete PIN data
        rc = delete_nv(esys_ctx, user_nv_index);
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Failed to delete PIN data: 0x%X\n", rc);
            ret = 1;
        } else {
            printf("✓ PIN data deleted for UID %d\n", target_uid);
        }
        
        // Delete lockout data
        rc = delete_nv(esys_ctx, user_lockout_index);
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Failed to delete lockout data: 0x%X\n", rc);
            ret = 1;
        } else {
            printf("✓ Lockout data deleted for UID %d\n", target_uid);
            ret = 0;
        }
        
        if (ret == 0) {
            syslog(LOG_NOTICE, "PIN and lockout data cleared for UID %u by UID %u", target_uid, current_uid);
        } else {
            syslog(LOG_ERR, "Failed to clear PIN data for UID %u by UID %u", target_uid, current_uid);
        }
        
        if (hmac_key != ESYS_TR_NONE) {
            Esys_TR_Close(esys_ctx, &hmac_key);
        }
        cleanup_tpm(&esys_ctx, &tcti_ctx);
        closelog();
        return ret;
    }
    
    // Regular PIN setup/change mode
    uid_t uid = current_uid;
    
    // Validate UID to prevent integer overflow attacks
    if (validate_uid_safe(uid) != 0) {
        fprintf(stderr, "UID %u is not safe for NV index calculation\n", uid);
        if (hmac_key != ESYS_TR_NONE) {
            Esys_TR_Close(esys_ctx, &hmac_key);
        }
        cleanup_tpm(&esys_ctx, &tcti_ctx);
        return 1;
    }
    
    uint32_t user_nv_index = TPM_NV_INDEX + uid;
    uint32_t user_lockout_index = TPM_NV_LOCKOUT_BASE + uid;
    
    printf("TPM PIN Setup Utility\n");
    printf("=====================\n");
    printf("Setting up PIN for UID %d\n", uid);
    
    // Check if we need to verify current PIN
    if (!is_root) {
        // Regular user - must verify current PIN if it exists
        uint8_t *test_data = NULL;
        size_t test_size = 0;
        rc = read_nv(esys_ctx, user_nv_index, &test_data, &test_size);
        
        if (rc == TSS2_RC_SUCCESS && test_data != NULL) {
            // PIN already exists, must verify current PIN
            free(test_data);
            
            char current_pin[PIN_MAX_LEN];
            printf("\nPIN already exists. You must enter your current PIN to change it.\n");
            if (read_pin_from_stdin("Enter current PIN: ", current_pin, sizeof(current_pin)) != 0) {
                fprintf(stderr, "Failed to read current PIN\n");
                if (hmac_key != ESYS_TR_NONE) {
                    Esys_TR_Close(esys_ctx, &hmac_key);
                }
                cleanup_tpm(&esys_ctx, &tcti_ctx);
                return 1;
            }
            
            // Read lockout policy from configuration file
            lockout_policy_t policy;
            
            int policy_rc = read_lockout_policy("./policy", &policy);
            if (policy_rc != 0) {
                fprintf(stderr, "Failed to read lockout policy\n");
                OPENSSL_cleanse(current_pin, sizeof(current_pin));
                if (hmac_key != ESYS_TR_NONE) {
                    Esys_TR_Close(esys_ctx, &hmac_key);
                }
                cleanup_tpm(&esys_ctx, &tcti_ctx);
                return 1;
            }
            // ATOMIC LOCKOUT CHECK: Increment counter BEFORE verification to prevent TOCTOU
            lockout_data_t lockout;
            int lockout_status = atomic_lockout_check_and_increment(esys_ctx, user_lockout_index, &policy, &lockout);
            if (lockout_status != 0) {
                // Either locked out (1) or error (-1) - deny
                OPENSSL_cleanse(current_pin, sizeof(current_pin));
                if (hmac_key != ESYS_TR_NONE) {
                    Esys_TR_Close(esys_ctx, &hmac_key);
                }
                cleanup_tpm(&esys_ctx, &tcti_ctx);
                return 1;
            }
            
            if (!verify_current_pin(esys_ctx, hmac_key, user_nv_index, current_pin)) {
                fprintf(stderr, "Error: Current PIN is incorrect\n");
                OPENSSL_cleanse(current_pin, sizeof(current_pin));
                
                // Failed attempt already recorded atomically
                if (policy.max_attempts > 0) {
                    fprintf(stderr, "Failed attempt %u/%u\n", 
                            lockout.failed_attempts, policy.max_attempts);
                }
                
                if (hmac_key != ESYS_TR_NONE) {
                    Esys_TR_Close(esys_ctx, &hmac_key);
                }
                cleanup_tpm(&esys_ctx, &tcti_ctx);
                return 1;
            }
            
            // PIN verified successfully - clear the lockout counter
            clear_lockout(esys_ctx, user_lockout_index);
            
            OPENSSL_cleanse(current_pin, sizeof(current_pin));
            printf("✓ Current PIN verified\n\n");
        } else if (rc != TSS2_RC_SUCCESS) {
            // Check if this is just a "handle doesn't exist" error (0x18B)
            uint16_t error_code = rc & 0xFFFF;
            if (error_code != 0x018B && error_code != TPM2_RC_HANDLE) {
                fprintf(stderr, "Error checking existing PIN: 0x%X\n", rc);
                if (hmac_key != ESYS_TR_NONE) {
                    Esys_TR_Close(esys_ctx, &hmac_key);
                }
                cleanup_tpm(&esys_ctx, &tcti_ctx);
                return 1;
            }
            // If error is 0x18B, this is first-time setup, no verification needed
        }
        // If handle doesn't exist, this is first-time setup, no verification needed
    } else {
        printf("Running as root - current PIN verification and lockout checks bypassed\n");
    }
    
    printf("\n");
    
    // Read PIN twice for confirmation
    if (read_pin_from_stdin("Enter new PIN: ", pin, sizeof(pin)) != 0) {
        fprintf(stderr, "Failed to read PIN\n");
        if (hmac_key != ESYS_TR_NONE) {
            Esys_TR_Close(esys_ctx, &hmac_key);
        }
        cleanup_tpm(&esys_ctx, &tcti_ctx);
        return 1;
    }
    int valid = validate_pin_requirements(pin);
    if (valid != 0) {
        fprintf(stderr, "PIN does not meet requirement. Must be at least %d digits and no more than %d digits.\n", 
                PIN_MIN_LEN, PIN_MAX_LEN - 1);
        OPENSSL_cleanse(pin, sizeof(pin));
        if (hmac_key != ESYS_TR_NONE) {
            Esys_TR_Close(esys_ctx, &hmac_key);
        }
        cleanup_tpm(&esys_ctx, &tcti_ctx);
        return 1;
    }
    
    if (strlen(pin) == 0) {
        fprintf(stderr, "PIN cannot be empty\n");
        OPENSSL_cleanse(pin, sizeof(pin));
        if (hmac_key != ESYS_TR_NONE) {
            Esys_TR_Close(esys_ctx, &hmac_key);
        }
        cleanup_tpm(&esys_ctx, &tcti_ctx);
        return 1;
    }
    
    if (read_pin_from_stdin("Confirm new PIN: ", pin_confirm, sizeof(pin_confirm)) != 0) {
        fprintf(stderr, "Failed to read PIN confirmation\n");
        OPENSSL_cleanse(pin, sizeof(pin));
        if (hmac_key != ESYS_TR_NONE) {
            Esys_TR_Close(esys_ctx, &hmac_key);
        }
        cleanup_tpm(&esys_ctx, &tcti_ctx);
        return 1;
    }
    
    if (strcmp(pin, pin_confirm) != 0) {
        fprintf(stderr, "PINs do not match\n");
        OPENSSL_cleanse(pin, sizeof(pin));
        OPENSSL_cleanse(pin_confirm, sizeof(pin_confirm));
        if (hmac_key != ESYS_TR_NONE) {
            Esys_TR_Close(esys_ctx, &hmac_key);
        }
        cleanup_tpm(&esys_ctx, &tcti_ctx);
        return 1;
    }
    
    OPENSSL_cleanse(pin_confirm, sizeof(pin_confirm));
    
    // Compute HMAC of the PIN
    unsigned char pin_hmac[HMAC_OUTPUT_SIZE];
    size_t hmac_len = sizeof(pin_hmac);
    rc = tpm_hmac(esys_ctx, hmac_key, (unsigned char*)pin, strlen(pin), pin_hmac, &hmac_len);
    OPENSSL_cleanse(pin, sizeof(pin));
    
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to compute HMAC: 0x%X\n", rc);
        OPENSSL_cleanse(pin_hmac, sizeof(pin_hmac));
        if (hmac_key != ESYS_TR_NONE) {
            Esys_TR_Close(esys_ctx, &hmac_key);
        }
        cleanup_tpm(&esys_ctx, &tcti_ctx);
        return 1;
    }
    
    // Write HMAC to NV
    printf("\nWriting PIN HMAC to TPM...\n");
    rc = write_nv(esys_ctx, user_nv_index, pin_hmac, HMAC_OUTPUT_SIZE);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to write PIN to NV: 0x%X\n", rc);
        syslog(LOG_ERR, "Failed to write PIN for UID %u", uid);
        ret = 1;
    } else {
        printf("✓ PIN successfully stored in TPM!\n");
        
        // Clear any existing lockout when PIN is changed (but preserve configuration)
        rc = clear_lockout(esys_ctx, user_lockout_index);
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Warning: Failed to clear lockout data: 0x%X\n", rc);
        } else {
            printf("✓ Lockout data cleared\n");
        }
        
        syslog(LOG_NOTICE, "PIN successfully set/changed for UID %u by UID %u", uid, current_uid);
        ret = 0;
    }
    
    // Cleanup
    OPENSSL_cleanse(pin_hmac, sizeof(pin_hmac));
    if (hmac_key != ESYS_TR_NONE) {
        Esys_TR_Close(esys_ctx, &hmac_key);
    }
    cleanup_tpm(&esys_ctx, &tcti_ctx);
    closelog();
    
    return ret;
}
