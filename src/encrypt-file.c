#include "encrypt-files-cb.h"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static gboolean
get_regular_file_size (gint fd, guint64 *size, GError **error)
{
    struct stat st;
    if (fstat (fd, &st) != 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                     "Unable to inspect input: %s", g_strerror (errno));
        return FALSE;
    }
    if (!S_ISREG (st.st_mode) || st.st_size < 0) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_INVALID_ARGUMENT,
                             "Input must be a regular file");
        return FALSE;
    }
    *size = (guint64)st.st_size;
    return TRUE;
}

gboolean
gtkcrypto_encrypt_file (const gchar *input_path,
                        const gchar *output_path,
                        const guint8 *password,
                        gsize password_len,
                        gboolean overwrite,
                        GCancellable *cancellable,
                        GError **error)
{
    g_return_val_if_fail (input_path != NULL, FALSE);
    g_return_val_if_fail (output_path != NULL, FALSE);
    g_return_val_if_fail (password != NULL || password_len == 0, FALSE);

    gboolean success = FALSE;
    gint input_fd = -1;
    gcry_cipher_hd_t cipher = NULL;
    GtkcryptoAtomicOutput output = { .fd = -1 };
    guint8 key[GTKCRYPTO_KEY_SIZE] = { 0 };
    guint8 header[GTKCRYPTO_V3_HEADER_SIZE] = { 0 };
    guint8 tag[GTKCRYPTO_TAG_SIZE] = { 0 };
    guint8 *plain = NULL;
    guint8 *encrypted = NULL;

    input_fd = g_open (input_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (input_fd < 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                     "Unable to open input: %s", g_strerror (errno));
        goto out;
    }

    guint64 plaintext_size;
    if (!get_regular_file_size (input_fd, &plaintext_size, error)) {
        goto out;
    }
    /* A single GCM stream is limited to 2^36 - 32 bytes; fail early. */
    if (plaintext_size > (G_GUINT64_CONSTANT (1) << 36) - 32) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_INVALID_ARGUMENT,
                             "Input is too large for AES-GCM (limit is 64 GiB)");
        goto out;
    }

    GtkcryptoV3Header hdr;
    gtkcrypto_v3_header_init (&hdr, plaintext_size);
    gtkcrypto_v3_header_encode (&hdr, header);

    if (!gtkcrypto_argon2id_derive (password, password_len, hdr.salt,
                                    hdr.kdf.time, hdr.kdf.memory_kib,
                                    hdr.kdf.lanes, key, error)) {
        goto out;
    }

    gcry_error_t gerr = gcry_cipher_open (&cipher, GCRY_CIPHER_AES256,
                                          GCRY_CIPHER_MODE_GCM, 0);
    if (gerr == 0) {
        gerr = gcry_cipher_setkey (cipher, key, sizeof key);
    }
    if (gerr == 0) {
        gerr = gcry_cipher_setiv (cipher, hdr.nonce, sizeof hdr.nonce);
    }
    if (gerr == 0) {
        gerr = gcry_cipher_authenticate (cipher, header, sizeof header);
    }
    if (gerr != 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                     "Unable to initialize encryption: %s",
                     gcry_strerror (gerr));
        goto out;
    }

    if (!gtkcrypto_atomic_output_open (&output, output_path, overwrite, error) ||
        !gtkcrypto_write_full (output.fd, header, sizeof header,
                               cancellable, error)) {
        goto out;
    }

    plain = g_try_malloc (FILE_BUFFER);
    encrypted = g_try_malloc (FILE_BUFFER);
    if (plain == NULL || encrypted == NULL) {
        g_set_error_literal (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                             "Unable to allocate encryption buffers");
        goto out;
    }

    guint64 done = 0;
    while (done < plaintext_size) {
        if (!gtkcrypto_check_cancelled (cancellable, error)) {
            goto out;
        }
        gsize wanted = (gsize)MIN ((guint64)FILE_BUFFER,
                                  plaintext_size - done);
        if (!gtkcrypto_read_full (input_fd, plain, wanted,
                                  cancellable, error)) {
            goto out;
        }
        if (done + wanted == plaintext_size) {
            gcry_cipher_final (cipher);
        }
        gerr = gcry_cipher_encrypt (cipher, encrypted, wanted, plain, wanted);
        if (gerr != 0) {
            g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                         "Encryption failed: %s", gcry_strerror (gerr));
            goto out;
        }
        if (!gtkcrypto_write_full (output.fd, encrypted, wanted,
                                   cancellable, error)) {
            goto out;
        }
        gtkcrypto_secure_clear (plain, wanted);
        gtkcrypto_secure_clear (encrypted, wanted);
        done += wanted;
        gtkcrypto_report_progress (done, plaintext_size);
    }

    if (plaintext_size == 0) {
        gcry_cipher_final (cipher);
    }
    gerr = gcry_cipher_gettag (cipher, tag, sizeof tag);
    if (gerr != 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                     "Unable to finalize authentication tag: %s",
                     gcry_strerror (gerr));
        goto out;
    }
    if (!gtkcrypto_write_full (output.fd, tag, sizeof tag,
                               cancellable, error) ||
        !gtkcrypto_atomic_output_commit (&output, error)) {
        goto out;
    }
    success = TRUE;

out:
    if (!success) {
        gtkcrypto_atomic_output_abort (&output);
    }
    if (input_fd >= 0) {
        close (input_fd);
    }
    if (cipher != NULL) {
        gcry_cipher_close (cipher);
    }
    gtkcrypto_secure_clear (key, sizeof key);
    gtkcrypto_secure_clear (plain, plain != NULL ? FILE_BUFFER : 0);
    gtkcrypto_secure_clear (encrypted, encrypted != NULL ? FILE_BUFFER : 0);
    g_free (plain);
    g_free (encrypted);
    return success;
}
