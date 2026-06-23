#include <glib.h>
#include <gcrypt.h>
#include <stdint.h>

#include "crypt-common.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    static gsize initialized;
    if (g_once_init_enter (&initialized)) {
        gcry_check_version ("1.10.1");
        gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
        g_once_init_leave (&initialized, 1);
    }

    static const guint8 password[] = "fuzz-password";
    GError *error = NULL;
    GBytes *result = gtkcrypto_decrypt_bytes_v3 (
        data, size, password, sizeof password - 1, &error);
    if (result != NULL) {
        g_bytes_unref (result);
    }
    g_clear_error (&error);
    return 0;
}
