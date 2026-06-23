#include "crypt-common.h"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <linux/fs.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

G_DEFINE_QUARK (gtkcrypto-error-quark, gtkcrypto_error)

void
gtkcrypto_secure_clear (gpointer data, gsize length)
{
    if (data == NULL) {
        return;
    }
#if defined(__GLIBC__) || defined(__linux__)
    explicit_bzero (data, length);
#else
    volatile guint8 *p = data;
    while (length-- > 0) {
        *p++ = 0;
    }
#endif
}

static void
set_errno_error (GError **error, const gchar *operation)
{
    g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                 "%s: %s", operation, g_strerror (errno));
}

gboolean
gtkcrypto_check_cancelled (GCancellable *cancellable, GError **error)
{
    if (cancellable != NULL && g_cancellable_is_cancelled (cancellable)) {
        g_set_error_literal (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CANCELLED,
                             "Operation cancelled");
        return FALSE;
    }
    return TRUE;
}

gboolean
gtkcrypto_read_full (gint fd, void *buffer, gsize length,
                     GCancellable *cancellable, GError **error)
{
    guint8 *p = buffer;
    gsize done = 0;

    while (done < length) {
        if (!gtkcrypto_check_cancelled (cancellable, error)) {
            return FALSE;
        }
        ssize_t n = read (fd, p + done, length - done);
        if (n == 0) {
            g_set_error_literal (error, GTKCRYPTO_ERROR,
                                 GTKCRYPTO_ERROR_INVALID_FORMAT,
                                 "Unexpected end of file");
            return FALSE;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            set_errno_error (error, "Read failed");
            return FALSE;
        }
        done += (gsize)n;
    }
    return TRUE;
}

gboolean
gtkcrypto_write_full (gint fd, const void *buffer, gsize length,
                      GCancellable *cancellable, GError **error)
{
    const guint8 *p = buffer;
    gsize done = 0;

    while (done < length) {
        if (!gtkcrypto_check_cancelled (cancellable, error)) {
            return FALSE;
        }
        ssize_t n = write (fd, p + done, length - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            set_errno_error (error, "Write failed");
            return FALSE;
        }
        if (n == 0) {
            g_set_error_literal (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                                 "Write made no progress");
            return FALSE;
        }
        done += (gsize)n;
    }
    return TRUE;
}

gboolean
gtkcrypto_pbkdf2_derive (const guint8 *password,
                         gsize password_len,
                         const guint8 *salt,
                         gsize salt_len,
                         guint iterations,
                         gsize key_len,
                         guint8 *key,
                         GError **error)
{
    gcry_error_t err = gcry_kdf_derive (password, password_len,
                                        GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                                        salt, salt_len, iterations,
                                        key_len, key);
    if (err != 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                     "PBKDF2 failed: %s", gcry_strerror (err));
        return FALSE;
    }
    return TRUE;
}

gboolean
gtkcrypto_argon2id_derive (const guint8 *password,
                           gsize password_len,
                           const guint8 salt[GTKCRYPTO_SALT_SIZE],
                           guint32 time_cost,
                           guint32 memory_kib,
                           guint32 lanes,
                           guint8 key[GTKCRYPTO_KEY_SIZE],
                           GError **error)
{
    if (time_cost < 1 || time_cost > 10 ||
        memory_kib < 8192 || memory_kib > 262144 ||
        lanes < 1 || lanes > 16) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_INVALID_FORMAT,
                             "Unsafe Argon2 parameters");
        return FALSE;
    }

    unsigned long params[4] = {
        GTKCRYPTO_KEY_SIZE, time_cost, memory_kib, lanes
    };
    gcry_kdf_hd_t hd = NULL;
    gcry_error_t err = gcry_kdf_open (&hd, GCRY_KDF_ARGON2,
                                      GCRY_KDF_ARGON2ID,
                                      params, G_N_ELEMENTS (params),
                                      password, password_len,
                                      salt, GTKCRYPTO_SALT_SIZE,
                                      NULL, 0, NULL, 0);
    if (err == 0) {
        err = gcry_kdf_compute (hd, NULL);
    }
    if (err == 0) {
        err = gcry_kdf_final (hd, GTKCRYPTO_KEY_SIZE, key);
    }
    if (hd != NULL) {
        gcry_kdf_close (hd);
    }
    if (err != 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                     "Argon2id failed: %s", gcry_strerror (err));
        return FALSE;
    }
    return TRUE;
}

gboolean
gtkcrypto_atomic_output_open (GtkcryptoAtomicOutput *output,
                              const gchar *destination,
                              gboolean overwrite,
                              GError **error)
{
    g_return_val_if_fail (output != NULL, FALSE);
    memset (output, 0, sizeof *output);
    output->fd = -1;

    if (!overwrite && g_file_test (destination, G_FILE_TEST_EXISTS)) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_EXISTS,
                     "Destination already exists: %s", destination);
        return FALSE;
    }

    g_autofree gchar *dir = g_path_get_dirname (destination);
    g_autofree gchar *base = g_path_get_basename (destination);
    output->path = g_strdup_printf ("%s/.%s.XXXXXX", dir, base);
    output->fd = g_mkstemp_full (output->path, O_RDWR | O_CLOEXEC, 0600);
    if (output->fd < 0) {
        set_errno_error (error, "Unable to create temporary output");
        g_clear_pointer (&output->path, g_free);
        return FALSE;
    }
    output->destination = g_strdup (destination);
    output->overwrite = overwrite;
    return TRUE;
}

gboolean
gtkcrypto_atomic_output_commit (GtkcryptoAtomicOutput *output, GError **error)
{
    if (fsync (output->fd) != 0) {
        set_errno_error (error, "Unable to synchronize output");
        return FALSE;
    }
    if (close (output->fd) != 0) {
        output->fd = -1;
        set_errno_error (error, "Unable to close output");
        return FALSE;
    }
    output->fd = -1;

    gint rename_result;
    if (output->overwrite) {
        rename_result = g_rename (output->path, output->destination);
    } else {
#if defined(SYS_renameat2) && defined(RENAME_NOREPLACE)
        rename_result = (gint)syscall (SYS_renameat2, AT_FDCWD, output->path,
                                      AT_FDCWD, output->destination,
                                      RENAME_NOREPLACE);
#else
        rename_result = link (output->path, output->destination);
        if (rename_result == 0) {
            rename_result = g_unlink (output->path);
        }
#endif
    }
    if (rename_result != 0) {
        if (!output->overwrite && errno == EEXIST) {
            g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_EXISTS,
                         "Destination already exists: %s",
                         output->destination);
            return FALSE;
        }
        set_errno_error (error, "Unable to publish output");
        return FALSE;
    }

    g_autofree gchar *dir = g_path_get_dirname (output->destination);
    gint dir_fd = g_open (dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (dir_fd >= 0) {
        (void)fsync (dir_fd);
        close (dir_fd);
    }

    g_clear_pointer (&output->path, g_free);
    g_clear_pointer (&output->destination, g_free);
    return TRUE;
}

void
gtkcrypto_atomic_output_abort (GtkcryptoAtomicOutput *output)
{
    if (output == NULL) {
        return;
    }
    if (output->fd >= 0) {
        close (output->fd);
    }
    if (output->path != NULL) {
        g_unlink (output->path);
    }
    g_clear_pointer (&output->path, g_free);
    g_clear_pointer (&output->destination, g_free);
    output->fd = -1;
}

static void
bytes_put_be16 (guint8 *p, guint16 value)
{
    value = GUINT16_TO_BE (value);
    memcpy (p, &value, sizeof value);
}

static void
bytes_put_be32 (guint8 *p, guint32 value)
{
    value = GUINT32_TO_BE (value);
    memcpy (p, &value, sizeof value);
}

static void
bytes_put_be64 (guint8 *p, guint64 value)
{
    value = GUINT64_TO_BE (value);
    memcpy (p, &value, sizeof value);
}

static guint16
bytes_get_be16 (const guint8 *p)
{
    guint16 value;
    memcpy (&value, p, sizeof value);
    return GUINT16_FROM_BE (value);
}

static guint32
bytes_get_be32 (const guint8 *p)
{
    guint32 value;
    memcpy (&value, p, sizeof value);
    return GUINT32_FROM_BE (value);
}

static guint64
bytes_get_be64 (const guint8 *p)
{
    guint64 value;
    memcpy (&value, p, sizeof value);
    return GUINT64_FROM_BE (value);
}

GBytes *
gtkcrypto_encrypt_bytes_v3 (const guint8 *plaintext,
                            gsize plaintext_len,
                            const guint8 *password,
                            gsize password_len,
                            GError **error)
{
    if (plaintext_len > G_MAXSIZE - GTKCRYPTO_V3_HEADER_SIZE -
                        GTKCRYPTO_TAG_SIZE) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_INVALID_ARGUMENT,
                             "Plaintext is too large");
        return NULL;
    }

    gsize container_len = GTKCRYPTO_V3_HEADER_SIZE + plaintext_len +
                          GTKCRYPTO_TAG_SIZE;
    guint8 *container = g_malloc0 (container_len);
    guint8 key[GTKCRYPTO_KEY_SIZE] = { 0 };
    gcry_cipher_hd_t cipher = NULL;
    GBytes *result = NULL;

    memcpy (container, "GTC3", 4);
    container[4] = 3;
    bytes_put_be16 (container + 5, GTKCRYPTO_V3_HEADER_SIZE);
    container[8] = 1;
    container[9] = 1;
    container[10] = GTKCRYPTO_SALT_SIZE;
    container[11] = GTKCRYPTO_NONCE_SIZE;
    container[12] = GTKCRYPTO_TAG_SIZE;
    bytes_put_be32 (container + 16, GTKCRYPTO_ARGON2_TIME);
    bytes_put_be32 (container + 20, GTKCRYPTO_ARGON2_MEMORY_KIB);
    bytes_put_be32 (container + 24, GTKCRYPTO_ARGON2_LANES);
    bytes_put_be64 (container + 28, plaintext_len);
    gcry_randomize (container + 36, GTKCRYPTO_SALT_SIZE, GCRY_STRONG_RANDOM);
    gcry_randomize (container + 68, GTKCRYPTO_NONCE_SIZE, GCRY_STRONG_RANDOM);

    if (!gtkcrypto_argon2id_derive (password, password_len, container + 36,
                                    GTKCRYPTO_ARGON2_TIME,
                                    GTKCRYPTO_ARGON2_MEMORY_KIB,
                                    GTKCRYPTO_ARGON2_LANES, key, error)) {
        goto out;
    }
    gcry_error_t gerr = gcry_cipher_open (&cipher, GCRY_CIPHER_AES256,
                                          GCRY_CIPHER_MODE_GCM, 0);
    if (gerr == 0) gerr = gcry_cipher_setkey (cipher, key, sizeof key);
    if (gerr == 0) gerr = gcry_cipher_setiv (cipher, container + 68,
                                             GTKCRYPTO_NONCE_SIZE);
    if (gerr == 0) gerr = gcry_cipher_authenticate (
        cipher, container, GTKCRYPTO_V3_HEADER_SIZE);
    if (gerr == 0) gcry_cipher_final (cipher);
    if (gerr == 0 && plaintext_len > 0) {
        gerr = gcry_cipher_encrypt (cipher,
                                    container + GTKCRYPTO_V3_HEADER_SIZE,
                                    plaintext_len, plaintext, plaintext_len);
    }
    if (gerr == 0) {
        gerr = gcry_cipher_gettag (
            cipher, container + GTKCRYPTO_V3_HEADER_SIZE + plaintext_len,
            GTKCRYPTO_TAG_SIZE);
    }
    if (gerr != 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                     "Text encryption failed: %s", gcry_strerror (gerr));
        goto out;
    }
    result = g_bytes_new_take (container, container_len);
    container = NULL;

out:
    if (cipher != NULL) gcry_cipher_close (cipher);
    gtkcrypto_secure_clear (key, sizeof key);
    if (container != NULL) {
        gtkcrypto_secure_clear (container, container_len);
        g_free (container);
    }
    return result;
}

GBytes *
gtkcrypto_decrypt_bytes_v3 (const guint8 *container,
                            gsize container_len,
                            const guint8 *password,
                            gsize password_len,
                            GError **error)
{
    if (container_len < GTKCRYPTO_V3_HEADER_SIZE + GTKCRYPTO_TAG_SIZE ||
        memcmp (container, "GTC3", 4) != 0 || container[4] != 3 ||
        bytes_get_be16 (container + 5) != GTKCRYPTO_V3_HEADER_SIZE ||
        container[7] != 0 || container[8] != 1 || container[9] != 1 ||
        container[10] != GTKCRYPTO_SALT_SIZE ||
        container[11] != GTKCRYPTO_NONCE_SIZE ||
        container[12] != GTKCRYPTO_TAG_SIZE ||
        container[13] != 0 || container[14] != 0 || container[15] != 0) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_INVALID_FORMAT,
                             "Invalid encrypted text container");
        return NULL;
    }
    guint64 plaintext_size64 = bytes_get_be64 (container + 28);
    if (plaintext_size64 > G_MAXSIZE ||
        container_len != GTKCRYPTO_V3_HEADER_SIZE + plaintext_size64 +
                         GTKCRYPTO_TAG_SIZE) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_INVALID_FORMAT,
                             "Encrypted text size mismatch");
        return NULL;
    }

    gsize plaintext_len = (gsize)plaintext_size64;
    guint8 *plaintext = g_malloc0 (plaintext_len + 1);
    guint8 key[GTKCRYPTO_KEY_SIZE] = { 0 };
    gcry_cipher_hd_t cipher = NULL;
    GBytes *result = NULL;

    if (!gtkcrypto_argon2id_derive (password, password_len, container + 36,
                                    bytes_get_be32 (container + 16),
                                    bytes_get_be32 (container + 20),
                                    bytes_get_be32 (container + 24),
                                    key, error)) {
        goto out;
    }
    gcry_error_t gerr = gcry_cipher_open (&cipher, GCRY_CIPHER_AES256,
                                          GCRY_CIPHER_MODE_GCM, 0);
    if (gerr == 0) gerr = gcry_cipher_setkey (cipher, key, sizeof key);
    if (gerr == 0) gerr = gcry_cipher_setiv (cipher, container + 68,
                                             GTKCRYPTO_NONCE_SIZE);
    if (gerr == 0) gerr = gcry_cipher_authenticate (
        cipher, container, GTKCRYPTO_V3_HEADER_SIZE);
    if (gerr == 0) gcry_cipher_final (cipher);
    if (gerr == 0 && plaintext_len > 0) {
        gerr = gcry_cipher_decrypt (
            cipher, plaintext, plaintext_len,
            container + GTKCRYPTO_V3_HEADER_SIZE, plaintext_len);
    }
    if (gerr == 0) {
        gerr = gcry_cipher_checktag (
            cipher,
            container + GTKCRYPTO_V3_HEADER_SIZE + plaintext_len,
            GTKCRYPTO_TAG_SIZE);
    }
    if (gerr != 0) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_AUTHENTICATION,
                             "Wrong password or corrupted encrypted text");
        goto out;
    }
    result = g_bytes_new_take (plaintext, plaintext_len + 1);
    plaintext = NULL;

out:
    if (cipher != NULL) gcry_cipher_close (cipher);
    gtkcrypto_secure_clear (key, sizeof key);
    if (plaintext != NULL) {
        gtkcrypto_secure_clear (plaintext, plaintext_len + 1);
        g_free (plaintext);
    }
    return result;
}
