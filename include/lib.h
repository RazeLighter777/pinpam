#include <security/pam_modules.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                               const char **argv);
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                            const char **argv);