#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <stdint.h>

#include "crypt-common.h"
#include "decrypt-files-cb.h"

/* Feeds arbitrary bytes to the file decryptor, which auto-detects GTC3 and
 * the legacy v1/v2 layouts, so every header parser is exercised. */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    static gsize initialized;
    static gchar *dir;
    if (g_once_init_enter (&initialized)) {
        gcry_check_version ("1.10.1");
        gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
        dir = g_dir_make_tmp ("gtkcrypto-fuzz-XXXXXX", NULL);
        g_once_init_leave (&initialized, 1);
    }
    if (dir == NULL) {
        return 0;
    }

    g_autofree gchar *input = g_build_filename (dir, "in", NULL);
    g_autofree gchar *output = g_build_filename (dir, "out", NULL);
    if (!g_file_set_contents (input, (const gchar *)data, (gssize)size, NULL)) {
        return 0;
    }

    static const guint8 password[] = "fuzz-password";
    GError *error = NULL;
    gtkcrypto_decrypt_file (input, output, password, sizeof password - 1,
                            TRUE, NULL, &error);
    g_clear_error (&error);
    g_unlink (output);
    g_unlink (input);
    return 0;
}
