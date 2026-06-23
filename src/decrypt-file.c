#include "decrypt-files-cb.h"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    guint version;
    gsize header_size;
    guint8 iv[16];
    gsize iv_size;
    guint8 salt[32];
    gint algo;
    gint mode;
    guint8 padding;
    guint iterations;
} LegacyHeader;

static guint16
get_be16 (const guint8 *p)
{
    guint16 value;
    memcpy (&value, p, sizeof value);
    return GUINT16_FROM_BE (value);
}

static guint32
get_be32 (const guint8 *p)
{
    guint32 value;
    memcpy (&value, p, sizeof value);
    return GUINT32_FROM_BE (value);
}

static guint64
get_be64 (const guint8 *p)
{
    guint64 value;
    memcpy (&value, p, sizeof value);
    return GUINT64_FROM_BE (value);
}

static guint32
get_u32 (const guint8 *p, gboolean big_endian)
{
    guint32 value;
    memcpy (&value, p, sizeof value);
    return big_endian ? GUINT32_FROM_BE (value) : GUINT32_FROM_LE (value);
}

static guint64
get_u64 (const guint8 *p, gboolean big_endian)
{
    guint64 value;
    memcpy (&value, p, sizeof value);
    return big_endian ? GUINT64_FROM_BE (value) : GUINT64_FROM_LE (value);
}

static gboolean
known_legacy_algorithm (gint algo)
{
    return algo == GCRY_CIPHER_AES256 ||
           algo == GCRY_CIPHER_TWOFISH ||
           algo == GCRY_CIPHER_SERPENT256 ||
           algo == GCRY_CIPHER_CAMELLIA256;
}

static gboolean
known_legacy_mode (gint mode)
{
    return mode == GCRY_CIPHER_MODE_CBC ||
           mode == GCRY_CIPHER_MODE_CTR ||
           mode == GCRY_CIPHER_MODE_GCM;
}

static gboolean
inspect_regular_file (gint fd, guint64 *size, GError **error)
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

static gboolean
seek_to (gint fd, guint64 offset, GError **error)
{
    if (offset > G_MAXINT64 ||
        lseek (fd, (off_t)offset, SEEK_SET) == (off_t)-1) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                     "Seek failed: %s", g_strerror (errno));
        return FALSE;
    }
    return TRUE;
}

static gboolean
verify_legacy_hmac (gint fd,
                    guint64 authenticated_size,
                    const guint8 key[64],
                    const guint8 expected[64],
                    GCancellable *cancellable,
                    GError **error)
{
    gcry_mac_hd_t mac = NULL;
    gcry_error_t gerr = gcry_mac_open (&mac, GCRY_MAC_HMAC_SHA3_512, 0, NULL);
    if (gerr == 0) {
        gerr = gcry_mac_setkey (mac, key, 64);
    }
    if (gerr != 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                     "Unable to initialize HMAC: %s", gcry_strerror (gerr));
        if (mac != NULL) {
            gcry_mac_close (mac);
        }
        return FALSE;
    }

    gboolean success = FALSE;
    guint8 *buffer = g_try_malloc (FILE_BUFFER);
    if (buffer == NULL) {
        g_set_error_literal (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                             "Unable to allocate HMAC buffer");
        goto out;
    }
    if (!seek_to (fd, 0, error)) {
        goto out;
    }

    guint64 done = 0;
    while (done < authenticated_size) {
        gsize wanted = (gsize)MIN ((guint64)FILE_BUFFER,
                                  authenticated_size - done);
        if (!gtkcrypto_read_full (fd, buffer, wanted, cancellable, error)) {
            goto out;
        }
        gerr = gcry_mac_write (mac, buffer, wanted);
        if (gerr != 0) {
            g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                         "HMAC calculation failed: %s", gcry_strerror (gerr));
            goto out;
        }
        done += wanted;
    }
    gerr = gcry_mac_verify (mac, expected, 64);
    if (gerr != 0) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_AUTHENTICATION,
                             "Wrong password or corrupted encrypted file");
        goto out;
    }
    success = TRUE;

out:
    gtkcrypto_secure_clear (buffer, buffer != NULL ? FILE_BUFFER : 0);
    g_free (buffer);
    gcry_mac_close (mac);
    return success;
}

static gboolean
decrypt_stream (gint input_fd,
                guint64 ciphertext_offset,
                guint64 ciphertext_size,
                const LegacyHeader *header,
                const guint8 *key,
                gint output_fd,
                GCancellable *cancellable,
                GError **error)
{
    gboolean success = FALSE;
    gcry_cipher_hd_t cipher = NULL;
    guint8 *encrypted = NULL;
    guint8 *plain = NULL;

    gcry_error_t gerr = gcry_cipher_open (&cipher, header->algo,
                                          header->mode, 0);
    if (gerr == 0) {
        gerr = gcry_cipher_setkey (cipher, key,
                                   gcry_cipher_get_algo_keylen (header->algo));
    }
    if (gerr == 0 && header->mode == GCRY_CIPHER_MODE_CBC) {
        gerr = gcry_cipher_setiv (cipher, header->iv, header->iv_size);
    } else if (gerr == 0 && header->mode == GCRY_CIPHER_MODE_CTR) {
        gerr = gcry_cipher_setctr (cipher, header->iv, header->iv_size);
    }
    if (gerr != 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                     "Unable to initialize legacy cipher: %s",
                     gcry_strerror (gerr));
        goto out;
    }
    if (!seek_to (input_fd, ciphertext_offset, error)) {
        goto out;
    }

    encrypted = g_try_malloc (FILE_BUFFER);
    plain = g_try_malloc (FILE_BUFFER);
    if (encrypted == NULL || plain == NULL) {
        g_set_error_literal (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                             "Unable to allocate decryption buffers");
        goto out;
    }

    guint64 done = 0;
    while (done < ciphertext_size) {
        gsize wanted = (gsize)MIN ((guint64)FILE_BUFFER,
                                  ciphertext_size - done);
        if (!gtkcrypto_read_full (input_fd, encrypted, wanted,
                                  cancellable, error)) {
            goto out;
        }
        gerr = gcry_cipher_decrypt (cipher, plain, wanted,
                                    encrypted, wanted);
        if (gerr != 0) {
            g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                         "Legacy decryption failed: %s", gcry_strerror (gerr));
            goto out;
        }

        gsize write_length = wanted;
        if (done + wanted == ciphertext_size &&
            header->mode == GCRY_CIPHER_MODE_CBC) {
            if (header->padding > 15 || header->padding > wanted) {
                g_set_error_literal (error, GTKCRYPTO_ERROR,
                                     GTKCRYPTO_ERROR_INVALID_FORMAT,
                                     "Invalid CBC padding");
                goto out;
            }
            write_length -= header->padding;
        }
        if (!gtkcrypto_write_full (output_fd, plain, write_length,
                                   cancellable, error)) {
            goto out;
        }
        gtkcrypto_secure_clear (encrypted, wanted);
        gtkcrypto_secure_clear (plain, wanted);
        done += wanted;
    }
    success = TRUE;

out:
    if (cipher != NULL) {
        gcry_cipher_close (cipher);
    }
    gtkcrypto_secure_clear (encrypted, encrypted != NULL ? FILE_BUFFER : 0);
    gtkcrypto_secure_clear (plain, plain != NULL ? FILE_BUFFER : 0);
    g_free (encrypted);
    g_free (plain);
    return success;
}

static gboolean
parse_v2_header (const guint8 bytes[GTKCRYPTO_V2_HEADER_SIZE],
                 gboolean big_endian,
                 LegacyHeader *header)
{
    if (memcmp (bytes, "GTC", 3) != 0 || bytes[3] != 2) {
        return FALSE;
    }
    memset (header, 0, sizeof *header);
    header->version = 2;
    header->header_size = GTKCRYPTO_V2_HEADER_SIZE;
    memcpy (header->iv, bytes + 4, 16);
    header->iv_size = bytes[20];
    memcpy (header->salt, bytes + 21, 32);
    header->algo = (gint)get_u32 (bytes + 53, big_endian);
    header->mode = (gint)get_u32 (bytes + 57, big_endian);
    header->padding = bytes[61];
    header->iterations = GTKCRYPTO_LEGACY_KDF_V2;

    gsize expected_iv = header->mode == GCRY_CIPHER_MODE_GCM ?
                        12 : gcry_cipher_get_algo_blklen (header->algo);
    return known_legacy_algorithm (header->algo) &&
           known_legacy_mode (header->mode) &&
           header->iv_size == expected_iv &&
           header->padding <= 15;
}

static gboolean
parse_v1_header (const guint8 *bytes,
                 gsize layout_size,
                 gboolean big_endian,
                 LegacyHeader *header)
{
    gsize size_field = layout_size == 72 ? 8 : 4;
    gsize salt_offset = 16 + size_field;
    gsize algo_offset = salt_offset + 32;
    gsize mode_offset = algo_offset + 4;
    gsize padding_offset = mode_offset + 4;
    guint64 iv_size = size_field == 8 ?
                      get_u64 (bytes + 16, big_endian) :
                      get_u32 (bytes + 16, big_endian);

    memset (header, 0, sizeof *header);
    header->version = 1;
    header->header_size = layout_size;
    memcpy (header->iv, bytes, 16);
    header->iv_size = (gsize)iv_size;
    memcpy (header->salt, bytes + salt_offset, 32);
    header->algo = (gint)get_u32 (bytes + algo_offset, big_endian);
    header->mode = (gint)get_u32 (bytes + mode_offset, big_endian);
    header->padding = bytes[padding_offset];
    header->iterations = GTKCRYPTO_LEGACY_KDF_V1;

    return known_legacy_algorithm (header->algo) &&
           (header->mode == GCRY_CIPHER_MODE_CBC ||
            header->mode == GCRY_CIPHER_MODE_CTR) &&
           header->iv_size == gcry_cipher_get_algo_blklen (header->algo) &&
           header->padding <= 15;
}

static gboolean
decrypt_legacy_candidate (gint input_fd,
                          guint64 file_size,
                          const LegacyHeader *header,
                          const guint8 *password,
                          gsize password_len,
                          gint output_fd,
                          GCancellable *cancellable,
                          GError **error)
{
    guint64 trailer = header->mode == GCRY_CIPHER_MODE_GCM ?
                      GTKCRYPTO_TAG_SIZE : GTKCRYPTO_LEGACY_HMAC_SIZE;
    if (file_size < header->header_size + trailer) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_INVALID_FORMAT,
                             "Encrypted file is truncated");
        return FALSE;
    }
    guint64 ciphertext_size = file_size - header->header_size - trailer;
    if (header->mode == GCRY_CIPHER_MODE_CBC &&
        ciphertext_size % gcry_cipher_get_algo_blklen (header->algo) != 0) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_INVALID_FORMAT,
                             "Invalid CBC ciphertext length");
        return FALSE;
    }

    gsize algo_key_len = gcry_cipher_get_algo_keylen (header->algo);
    guint8 derived[GTKCRYPTO_KEY_SIZE + 64] = { 0 };
    gboolean success = FALSE;
    if (!gtkcrypto_pbkdf2_derive (password, password_len,
                                  header->salt, sizeof header->salt,
                                  header->iterations,
                                  algo_key_len + 64, derived, error)) {
        goto out;
    }

    if (header->mode != GCRY_CIPHER_MODE_GCM) {
        guint8 expected[64];
        if (!seek_to (input_fd, file_size - 64, error) ||
            !gtkcrypto_read_full (input_fd, expected, sizeof expected,
                                  cancellable, error) ||
            !verify_legacy_hmac (input_fd, file_size - 64,
                                 derived + algo_key_len, expected,
                                 cancellable, error)) {
            goto out;
        }
        success = decrypt_stream (input_fd, header->header_size,
                                  ciphertext_size, header, derived,
                                  output_fd, cancellable, error);
        goto out;
    }

    guint8 stored_tag[GTKCRYPTO_TAG_SIZE];
    if (!seek_to (input_fd, file_size - sizeof stored_tag, error) ||
        !gtkcrypto_read_full (input_fd, stored_tag, sizeof stored_tag,
                              cancellable, error)) {
        goto out;
    }

    gcry_cipher_hd_t cipher = NULL;
    gcry_error_t gerr = gcry_cipher_open (&cipher, header->algo,
                                          GCRY_CIPHER_MODE_GCM, 0);
    if (gerr == 0) {
        gerr = gcry_cipher_setkey (cipher, derived, algo_key_len);
    }
    if (gerr == 0) {
        gerr = gcry_cipher_setiv (cipher, header->iv, header->iv_size);
    }
    if (gerr != 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                     "Unable to initialize legacy GCM: %s",
                     gcry_strerror (gerr));
        if (cipher != NULL) {
            gcry_cipher_close (cipher);
        }
        goto out;
    }

    guint8 *encrypted = g_try_malloc (FILE_BUFFER);
    guint8 *plain = g_try_malloc (FILE_BUFFER);
    if (encrypted == NULL || plain == NULL ||
        !seek_to (input_fd, header->header_size, error)) {
        if (encrypted == NULL || plain == NULL) {
            g_set_error_literal (error, GTKCRYPTO_ERROR,
                                 GTKCRYPTO_ERROR_IO,
                                 "Unable to allocate decryption buffers");
        }
        g_free (encrypted);
        g_free (plain);
        gcry_cipher_close (cipher);
        goto out;
    }

    guint64 done = 0;
    while (done < ciphertext_size) {
        gsize wanted = (gsize)MIN ((guint64)FILE_BUFFER,
                                  ciphertext_size - done);
        if (!gtkcrypto_read_full (input_fd, encrypted, wanted,
                                  cancellable, error)) {
            goto gcm_out;
        }
        if (done + wanted == ciphertext_size) {
            gcry_cipher_final (cipher);
        }
        gerr = gcry_cipher_decrypt (cipher, plain, wanted,
                                    encrypted, wanted);
        if (gerr != 0 ||
            !gtkcrypto_write_full (output_fd, plain, wanted,
                                   cancellable, error)) {
            if (gerr != 0) {
                g_set_error (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_CRYPTO,
                             "Legacy GCM decryption failed: %s",
                             gcry_strerror (gerr));
            }
            goto gcm_out;
        }
        done += wanted;
    }
    if (ciphertext_size == 0) {
        gcry_cipher_final (cipher);
    }
    gerr = gcry_cipher_checktag (cipher, stored_tag, sizeof stored_tag);
    if (gerr != 0) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_AUTHENTICATION,
                             "Wrong password or corrupted encrypted file");
        goto gcm_out;
    }
    success = TRUE;

gcm_out:
    gtkcrypto_secure_clear (encrypted, encrypted != NULL ? FILE_BUFFER : 0);
    gtkcrypto_secure_clear (plain, plain != NULL ? FILE_BUFFER : 0);
    g_free (encrypted);
    g_free (plain);
    gcry_cipher_close (cipher);
out:
    gtkcrypto_secure_clear (derived, sizeof derived);
    return success;
}

static gboolean
decrypt_v3 (gint input_fd,
            guint64 file_size,
            const guint8 header[GTKCRYPTO_V3_HEADER_SIZE],
            const guint8 *password,
            gsize password_len,
            gint output_fd,
            GCancellable *cancellable,
            GError **error)
{
    if (memcmp (header, "GTC3", 4) != 0 ||
        header[4] != 3 ||
        get_be16 (header + 5) != GTKCRYPTO_V3_HEADER_SIZE ||
        header[7] != 0 || header[8] != 1 || header[9] != 1 ||
        header[10] != GTKCRYPTO_SALT_SIZE ||
        header[11] != GTKCRYPTO_NONCE_SIZE ||
        header[12] != GTKCRYPTO_TAG_SIZE ||
        header[13] != 0 || header[14] != 0 || header[15] != 0) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_INVALID_FORMAT,
                             "Invalid or unsupported GTC3 header");
        return FALSE;
    }

    guint32 time_cost = get_be32 (header + 16);
    guint32 memory_kib = get_be32 (header + 20);
    guint32 lanes = get_be32 (header + 24);
    guint64 plaintext_size = get_be64 (header + 28);
    if (plaintext_size > G_MAXUINT64 - GTKCRYPTO_V3_HEADER_SIZE -
                         GTKCRYPTO_TAG_SIZE ||
        file_size != GTKCRYPTO_V3_HEADER_SIZE + plaintext_size +
                     GTKCRYPTO_TAG_SIZE) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_INVALID_FORMAT,
                             "GTC3 file size does not match its header");
        return FALSE;
    }

    guint8 key[GTKCRYPTO_KEY_SIZE] = { 0 };
    guint8 stored_tag[GTKCRYPTO_TAG_SIZE];
    gboolean success = FALSE;
    gcry_cipher_hd_t cipher = NULL;
    guint8 *encrypted = NULL;
    guint8 *plain = NULL;

    if (!gtkcrypto_argon2id_derive (password, password_len, header + 36,
                                    time_cost, memory_kib, lanes,
                                    key, error) ||
        !seek_to (input_fd, file_size - sizeof stored_tag, error) ||
        !gtkcrypto_read_full (input_fd, stored_tag, sizeof stored_tag,
                              cancellable, error)) {
        goto out;
    }

    gcry_error_t gerr = gcry_cipher_open (&cipher, GCRY_CIPHER_AES256,
                                          GCRY_CIPHER_MODE_GCM, 0);
    if (gerr == 0) {
        gerr = gcry_cipher_setkey (cipher, key, sizeof key);
    }
    if (gerr == 0) {
        gerr = gcry_cipher_setiv (cipher, header + 68,
                                  GTKCRYPTO_NONCE_SIZE);
    }
    if (gerr == 0) {
        gerr = gcry_cipher_authenticate (cipher, header,
                                         GTKCRYPTO_V3_HEADER_SIZE);
    }
    if (gerr != 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CRYPTO,
                     "Unable to initialize GTC3 decryption: %s",
                     gcry_strerror (gerr));
        goto out;
    }
    if (!seek_to (input_fd, GTKCRYPTO_V3_HEADER_SIZE, error)) {
        goto out;
    }

    encrypted = g_try_malloc (FILE_BUFFER);
    plain = g_try_malloc (FILE_BUFFER);
    if (encrypted == NULL || plain == NULL) {
        g_set_error_literal (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                             "Unable to allocate decryption buffers");
        goto out;
    }

    guint64 done = 0;
    while (done < plaintext_size) {
        gsize wanted = (gsize)MIN ((guint64)FILE_BUFFER,
                                  plaintext_size - done);
        if (!gtkcrypto_read_full (input_fd, encrypted, wanted,
                                  cancellable, error)) {
            goto out;
        }
        if (done + wanted == plaintext_size) {
            gcry_cipher_final (cipher);
        }
        gerr = gcry_cipher_decrypt (cipher, plain, wanted,
                                    encrypted, wanted);
        if (gerr != 0 ||
            !gtkcrypto_write_full (output_fd, plain, wanted,
                                   cancellable, error)) {
            if (gerr != 0) {
                g_set_error (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_CRYPTO,
                             "GTC3 decryption failed: %s",
                             gcry_strerror (gerr));
            }
            goto out;
        }
        done += wanted;
    }
    if (plaintext_size == 0) {
        gcry_cipher_final (cipher);
    }
    gerr = gcry_cipher_checktag (cipher, stored_tag, sizeof stored_tag);
    if (gerr != 0) {
        g_set_error_literal (error, GTKCRYPTO_ERROR,
                             GTKCRYPTO_ERROR_AUTHENTICATION,
                             "Wrong password or corrupted encrypted file");
        goto out;
    }
    success = TRUE;

out:
    if (cipher != NULL) {
        gcry_cipher_close (cipher);
    }
    gtkcrypto_secure_clear (key, sizeof key);
    gtkcrypto_secure_clear (encrypted, encrypted != NULL ? FILE_BUFFER : 0);
    gtkcrypto_secure_clear (plain, plain != NULL ? FILE_BUFFER : 0);
    g_free (encrypted);
    g_free (plain);
    return success;
}

gboolean
gtkcrypto_decrypt_file (const gchar *input_path,
                        const gchar *output_path,
                        const guint8 *password,
                        gsize password_len,
                        gboolean overwrite,
                        GCancellable *cancellable,
                        GError **error)
{
    gboolean success = FALSE;
    gint input_fd = -1;
    GtkcryptoAtomicOutput output = { .fd = -1 };
    guint8 prefix[GTKCRYPTO_V3_HEADER_SIZE] = { 0 };
    g_autofree guint8 *legacy_password = g_malloc0 (password_len + 1);
    guint64 file_size;

    memcpy (legacy_password, password, password_len);

    input_fd = g_open (input_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (input_fd < 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                     "Unable to open input: %s", g_strerror (errno));
        goto out;
    }
    if (!inspect_regular_file (input_fd, &file_size, error) ||
        file_size < 4) {
        if (error == NULL || *error == NULL) {
            g_set_error_literal (error, GTKCRYPTO_ERROR,
                                 GTKCRYPTO_ERROR_INVALID_FORMAT,
                                 "Encrypted file is too short");
        }
        goto out;
    }
    gsize prefix_size = (gsize)MIN (file_size, (guint64)sizeof prefix);
    if (!gtkcrypto_read_full (input_fd, prefix, prefix_size,
                              cancellable, error) ||
        !gtkcrypto_atomic_output_open (&output, output_path,
                                       overwrite, error)) {
        goto out;
    }

    if (prefix_size >= GTKCRYPTO_V3_HEADER_SIZE &&
        memcmp (prefix, "GTC3", 4) == 0) {
        success = decrypt_v3 (input_fd, file_size, prefix, password,
                              password_len, output.fd, cancellable, error);
    } else if (prefix_size >= GTKCRYPTO_V2_HEADER_SIZE &&
               memcmp (prefix, "GTC", 3) == 0) {
        LegacyHeader header;
        gboolean parsed = parse_v2_header (prefix, FALSE, &header) ||
                          parse_v2_header (prefix, TRUE, &header);
        if (!parsed) {
            g_set_error_literal (error, GTKCRYPTO_ERROR,
                                 GTKCRYPTO_ERROR_INVALID_FORMAT,
                                 "Invalid GTC2 header");
        } else {
            gsize legacy_password_len =
                (gsize)g_utf8_strlen ((const gchar *)password,
                                      (gssize)password_len) + 1;
            legacy_password_len = MIN (legacy_password_len, password_len + 1);
            success = decrypt_legacy_candidate (input_fd, file_size, &header,
                                                legacy_password,
                                                legacy_password_len,
                                                output.fd, cancellable, error);
        }
    } else {
        const gsize layouts[] = { 72, 64 };
        const gboolean byte_orders[] = { FALSE, TRUE };
        gboolean found = FALSE;
        for (gsize i = 0; i < G_N_ELEMENTS (layouts) && !found; i++) {
            if (file_size < layouts[i] + GTKCRYPTO_LEGACY_HMAC_SIZE ||
                prefix_size < layouts[i]) {
                continue;
            }
            for (gsize j = 0; j < G_N_ELEMENTS (byte_orders); j++) {
                LegacyHeader candidate;
                if (!parse_v1_header (prefix, layouts[i], byte_orders[j],
                                      &candidate)) {
                    continue;
                }
                gsize legacy_password_len =
                    (gsize)g_utf8_strlen ((const gchar *)password,
                                          (gssize)password_len) + 1;
                legacy_password_len = MIN (legacy_password_len,
                                           password_len + 1);
                g_clear_error (error);
                if (decrypt_legacy_candidate (input_fd, file_size, &candidate,
                                              legacy_password,
                                              legacy_password_len,
                                              output.fd, cancellable, error)) {
                    found = TRUE;
                    success = TRUE;
                    break;
                }
                if (ftruncate (output.fd, 0) != 0 ||
                    lseek (output.fd, 0, SEEK_SET) == (off_t)-1) {
                    g_set_error (error, GTKCRYPTO_ERROR,
                                 GTKCRYPTO_ERROR_IO,
                                 "Unable to reset temporary output: %s",
                                 g_strerror (errno));
                    goto out;
                }
            }
        }
        if (!found && (error == NULL || *error == NULL)) {
            g_set_error_literal (error, GTKCRYPTO_ERROR,
                                 GTKCRYPTO_ERROR_INVALID_FORMAT,
                                 "File is not a supported GTKCrypto format");
        }
    }

    if (success) {
        success = gtkcrypto_atomic_output_commit (&output, error);
    }

out:
    if (!success) {
        gtkcrypto_atomic_output_abort (&output);
    }
    if (input_fd >= 0) {
        close (input_fd);
    }
    gtkcrypto_secure_clear (legacy_password, password_len + 1);
    return success;
}

gpointer
decrypt_file (const gchar *input_file_path, const gchar *pwd)
{
    g_autofree gchar *output = NULL;
    if (g_str_has_suffix (input_file_path, ".enc")) {
        output = g_strndup (input_file_path, strlen (input_file_path) - 4);
    } else {
        output = g_strconcat (input_file_path, ".decrypted", NULL);
    }

    g_autoptr(GError) error = NULL;
    if (!gtkcrypto_decrypt_file (input_file_path, output,
                                 (const guint8 *)pwd, strlen (pwd),
                                 FALSE, NULL, &error)) {
        return g_strdup (error->message);
    }
    return NULL;
}
