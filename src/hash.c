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
    gcry_md_hd_t hd = NULL;
    gcry_error_t gerr = gcry_md_open (&hd, hash_algo, 0);
    if (gerr != 0) {
        g_printerr ("Unable to initialize hash: %s\n", gcry_strerror (gerr));
        return NULL;
    }

    gpointer status = compute_hash (&hd, filename);
    if (status != HASH_COMPUTED) {
        gcry_md_close (hd);
        return NULL;
    }
    return finalize_hash (&hd, hash_algo, digest_size);
}

gpointer
compute_hash (gcry_md_hd_t *hd, const gchar *filename)
{
    gint fd = g_open (filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0) {
        g_printerr ("%s: %s\n", filename, g_strerror (errno));
        return HASH_ERROR;
    }

    guint8 *buffer = g_try_malloc (FILE_BUFFER);
    if (buffer == NULL) {
        close (fd);
        return HASH_ERROR;
    }

    gpointer result = HASH_COMPUTED;
    for (;;) {
        ssize_t n = read (fd, buffer, FILE_BUFFER);
        if (n == 0) {
            break;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            g_printerr ("%s: %s\n", filename, g_strerror (errno));
            result = HASH_ERROR;
            break;
        }
        gcry_md_write (*hd, buffer, (gsize)n);
    }

    gtkcrypto_secure_clear (buffer, FILE_BUFFER);
    g_free (buffer);
    close (fd);
    return result;
}

gchar *
finalize_hash (gcry_md_hd_t *hd, gint algo, gint digest_size)
{
    gcry_md_final (*hd);
    const guchar *hash = gcry_md_read (*hd, algo);
    if (hash == NULL) {
        gcry_md_close (*hd);
        return NULL;
    }

    gchar *result = g_malloc ((gsize)digest_size * 2 + 1);
    for (gint i = 0; i < digest_size; i++) {
        g_snprintf (result + (i * 2), 3, "%02x", hash[i]);
    }
    result[digest_size * 2] = '\0';
    gcry_md_close (*hd);
    return result;
}
