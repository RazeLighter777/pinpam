#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h> // for CRYPTO_memcmp

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                               const char **argv);
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                            const char **argv);