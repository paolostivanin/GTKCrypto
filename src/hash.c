#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <unistd.h>

#include "crypt-common.h"
#include "hash.h"
#include "gtkcrypto.h"

gchar *
get_file_hash (const gchar *filename,
               gint hash_algo,
               gint digest_size)
{
    gchar *hex[1] = { NULL };
    if (!gtkcrypto_hash_file (filename, &hash_algo, &digest_size, 1, NULL,
                              hex, NULL)) {
        return NULL;
    }
    return hex[0];
}

gboolean
gtkcrypto_hash_fd (gint fd, const gchar *name, const gint *algos,
                   const gint *digest_sizes, guint n_algos,
                   GCancellable *cancellable, gchar **hex_out,
                   GError **error)
{
    g_return_val_if_fail (fd >= 0, FALSE);
    g_return_val_if_fail (n_algos > 0 && algos != NULL, FALSE);

    gboolean success = FALSE;
    gcry_md_hd_t hd = NULL;
    guint8 *buffer = NULL;

    for (guint i = 0; i < n_algos; i++) {
        hex_out[i] = NULL;
    }

    gcry_error_t gerr = gcry_md_open (&hd, 0, 0);
    for (guint i = 0; gerr == 0 && i < n_algos; i++) {
        gerr = gcry_md_enable (hd, algos[i]);
    }
    if (gerr != 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                     "Unable to initialize hash: %s", gcry_strerror (gerr));
        goto out;
    }

    buffer = g_try_malloc (FILE_BUFFER);
    if (buffer == NULL) {
        g_set_error_literal (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                             "Unable to allocate read buffer");
        goto out;
    }

    for (;;) {
        if (!gtkcrypto_check_cancelled (cancellable, error)) {
            goto out;
        }
        ssize_t n = read (fd, buffer, FILE_BUFFER);
        if (n == 0) {
            break;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                         "%s: %s", name, g_strerror (errno));
            goto out;
        }
        gcry_md_write (hd, buffer, (gsize)n);
    }

    gcry_md_final (hd);
    for (guint i = 0; i < n_algos; i++) {
        const guchar *digest = gcry_md_read (hd, algos[i]);
        if (digest == NULL) {
            g_set_error_literal (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                                 "Unable to read digest");
            goto out;
        }
        hex_out[i] = g_malloc ((gsize)digest_sizes[i] * 2 + 1);
        for (gint j = 0; j < digest_sizes[i]; j++) {
            g_snprintf (hex_out[i] + (j * 2), 3, "%02x", digest[j]);
        }
    }
    success = TRUE;

out:
    if (!success) {
        for (guint i = 0; i < n_algos; i++) {
            g_clear_pointer (&hex_out[i], g_free);
        }
    }
    if (buffer != NULL) {
        gtkcrypto_secure_clear (buffer, FILE_BUFFER);
        g_free (buffer);
    }
    if (hd != NULL) {
        gcry_md_close (hd);
    }
    return success;
}

gboolean
gtkcrypto_hash_file (const gchar *file_path, const gint *algos,
                     const gint *digest_sizes, guint n_algos,
                     GCancellable *cancellable, gchar **hex_out,
                     GError **error)
{
    g_return_val_if_fail (file_path != NULL, FALSE);

    gint fd = g_open (file_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                     "%s: %s", file_path, g_strerror (errno));
        return FALSE;
    }
    gboolean ok = gtkcrypto_hash_fd (fd, file_path, algos, digest_sizes,
                                     n_algos, cancellable, hex_out, error);
    close (fd);
    return ok;
}
