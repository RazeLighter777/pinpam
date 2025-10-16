#include "lib.h"


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

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    ESYS_CONTEXT *esys_context = NULL;
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;
    size_t tcti_size = 0;
    rc = initialize_tpm(&esys_context, &tcti_context, &tcti_size);
    printf("TCTI size: %zu\n", tcti_size);
    printf("RC: 0x%X\n", rc);
    printf("ESYS_CONTEXT: %p\n", esys_context);
    printf("TCTI_CONTEXT: %p\n", tcti_context);
    if (rc != TSS2_RC_SUCCESS) {
        return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;

}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SILENT;
}