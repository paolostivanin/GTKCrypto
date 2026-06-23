#include "encrypt-files-cb.h"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    V3_OFFSET_VERSION = 4,
    V3_OFFSET_HEADER_LENGTH = 5,
    V3_OFFSET_FLAGS = 7,
    V3_OFFSET_CIPHER = 8,
    V3_OFFSET_KDF = 9,
    V3_OFFSET_SALT_LENGTH = 10,
    V3_OFFSET_NONCE_LENGTH = 11,
    V3_OFFSET_TAG_LENGTH = 12,
    V3_OFFSET_RESERVED = 13,
    V3_OFFSET_TIME = 16,
    V3_OFFSET_MEMORY = 20,
    V3_OFFSET_LANES = 24,
    V3_OFFSET_PLAINTEXT_SIZE = 28,
    V3_OFFSET_SALT = 36,
    V3_OFFSET_NONCE = 68,
};

static void
put_be16 (guint8 *p, guint16 value)
{
    value = GUINT16_TO_BE (value);
    memcpy (p, &value, sizeof value);
}

static void
put_be32 (guint8 *p, guint32 value)
{
    value = GUINT32_TO_BE (value);
    memcpy (p, &value, sizeof value);
}

static void
put_be64 (guint8 *p, guint64 value)
{
    value = GUINT64_TO_BE (value);
    memcpy (p, &value, sizeof value);
}

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

    memcpy (header, "GTC3", 4);
    header[V3_OFFSET_VERSION] = 3;
    put_be16 (header + V3_OFFSET_HEADER_LENGTH, GTKCRYPTO_V3_HEADER_SIZE);
    header[V3_OFFSET_FLAGS] = 0;
    header[V3_OFFSET_CIPHER] = 1; /* AES-256-GCM */
    header[V3_OFFSET_KDF] = 1; /* Argon2id */
    header[V3_OFFSET_SALT_LENGTH] = GTKCRYPTO_SALT_SIZE;
    header[V3_OFFSET_NONCE_LENGTH] = GTKCRYPTO_NONCE_SIZE;
    header[V3_OFFSET_TAG_LENGTH] = GTKCRYPTO_TAG_SIZE;
    memset (header + V3_OFFSET_RESERVED, 0, 3);
    put_be32 (header + V3_OFFSET_TIME, GTKCRYPTO_ARGON2_TIME);
    put_be32 (header + V3_OFFSET_MEMORY, GTKCRYPTO_ARGON2_MEMORY_KIB);
    put_be32 (header + V3_OFFSET_LANES, GTKCRYPTO_ARGON2_LANES);
    put_be64 (header + V3_OFFSET_PLAINTEXT_SIZE, plaintext_size);
    gcry_randomize (header + V3_OFFSET_SALT, GTKCRYPTO_SALT_SIZE,
                    GCRY_STRONG_RANDOM);
    gcry_randomize (header + V3_OFFSET_NONCE, GTKCRYPTO_NONCE_SIZE,
                    GCRY_STRONG_RANDOM);

    if (!gtkcrypto_argon2id_derive (password, password_len,
                                    header + V3_OFFSET_SALT,
                                    GTKCRYPTO_ARGON2_TIME,
                                    GTKCRYPTO_ARGON2_MEMORY_KIB,
                                    GTKCRYPTO_ARGON2_LANES,
                                    key, error)) {
        goto out;
    }

    gcry_error_t gerr = gcry_cipher_open (&cipher, GCRY_CIPHER_AES256,
                                          GCRY_CIPHER_MODE_GCM, 0);
    if (gerr == 0) {
        gerr = gcry_cipher_setkey (cipher, key, sizeof key);
    }
    if (gerr == 0) {
        gerr = gcry_cipher_setiv (cipher, header + V3_OFFSET_NONCE,
                                  GTKCRYPTO_NONCE_SIZE);
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

gpointer
encrypt_file (const gchar *input_file_path,
              const gchar *pwd,
              const gchar *algo,
              const gchar *algo_mode)
{
    (void)algo;
    (void)algo_mode;
    g_autofree gchar *output = g_strconcat (input_file_path, ".enc", NULL);
    g_autoptr(GError) error = NULL;

    if (!gtkcrypto_encrypt_file (input_file_path, output,
                                 (const guint8 *)pwd, strlen (pwd),
                                 FALSE, NULL, &error)) {
        return g_strdup (error->message);
    }
    return NULL;
}
