#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <gcrypt.h>
#include <string.h>
#include "gtkcrypto.h"
#include "hash.h"
#include "crypt-common.h"
#include "cleanup.h"


static GFile    *get_g_file_with_encrypted_data (GFileInputStream  *in_stream,
                                                 goffset            file_size);

static gboolean  compare_hmac                   (guchar            *hmac_key,
                                                 guchar            *original_hmac,
                                                 GFile             *encrypted_data);

gpointer         decrypt                        (Metadata          *header_metadata,
                                                 CryptoKeys        *dec_keys,
                                                 GFile             *enc_data,
                                                 goffset            enc_data_size,
                                                 GFileOutputStream *ostream);

static gpointer  decrypt_gcm                    (Metadata          *header_metadata,
                                                 CryptoKeys        *dec_keys,
                                                 GFileInputStream  *in_stream,
                                                 goffset            enc_data_size,
                                                 const guchar      *stored_tag,
                                                 GFileOutputStream *ostream);


gpointer
decrypt_file (const gchar *input_file_path,
              const gchar *pwd)
{
    GError *err = NULL;
    gchar *err_msg = NULL;

    goffset file_size = get_file_size (input_file_path);
    if (file_size == -1) {
        return g_strdup ("Couldn't get the file size.");
    }
    if (file_size < (goffset) sizeof (Metadata)) {
        return g_strdup ("The selected file is not encrypted.");
    }

    GFile *in_file = g_file_new_for_path (input_file_path);
    GFileInputStream *in_stream = g_file_read (in_file, NULL, &err);
    if (err != NULL) {
        err_msg = g_strdup (err->message);
        g_clear_error (&err);
        g_object_unref (in_file);
        if (in_stream) {
            g_input_stream_close (G_INPUT_STREAM (in_stream), NULL, NULL);
            g_object_unref (in_stream);
        }
        return err_msg;
    }

    Metadata *header_metadata = g_new0 (Metadata, 1);

    gssize rw_len = g_input_stream_read (G_INPUT_STREAM (in_stream), header_metadata, sizeof (Metadata), NULL, &err);
    if (rw_len == -1) {
        err_msg = g_strdup (err->message);
        g_clear_error (&err);
        g_object_unref (in_file);
        gstream_cleanup (in_stream, NULL);
        g_free (header_metadata);
        return err_msg;
    }

    /* Verify magic bytes */
    if (header_metadata->magic[0] != METADATA_MAGIC_0 ||
        header_metadata->magic[1] != METADATA_MAGIC_1 ||
        header_metadata->magic[2] != METADATA_MAGIC_2) {
        g_object_unref (in_file);
        gstream_cleanup (in_stream, NULL);
        g_free (header_metadata);
        return g_strdup ("This file was not encrypted by GTKCrypto, or was created with an incompatible older version.");
    }

    guint kdf_iterations = (header_metadata->version >= METADATA_VERSION) ? KDF_ITERATIONS : KDF_ITERATIONS_LEGACY;

    gchar *output_file_path;
    if (!g_str_has_suffix (input_file_path, ".enc")) {
        g_printerr ("The selected file may not be encrypted\n");
        output_file_path = g_strconcat (input_file_path, ".decrypted", NULL);
    } else {
        output_file_path = g_strndup (input_file_path, (gsize) g_utf8_strlen (input_file_path, -1) - 4);
    }
    GFile *out_file = g_file_new_for_path (output_file_path);
    GFileOutputStream *out_stream = g_file_append_to (out_file, G_FILE_CREATE_REPLACE_DESTINATION, NULL, &err);
    if (err != NULL) {
        err_msg = g_strdup (err->message);
        g_clear_error (&err);
        gfile_cleanup (in_file, out_file);
        gstream_cleanup (in_stream, out_stream);
        g_free (output_file_path);
        g_free (header_metadata);
        return err_msg;
    }

    CryptoKeys *decryption_keys = g_new0 (CryptoKeys, 1);

    if (!setup_keys (pwd, gcry_cipher_get_algo_keylen (header_metadata->algo), kdf_iterations, header_metadata, decryption_keys)) {
        crypto_keys_cleanup (decryption_keys);
        gfile_cleanup (in_file, out_file);
        gstream_cleanup (in_stream, out_stream);
        g_free (output_file_path);
        g_free (header_metadata);
        return g_strdup ("Error during key derivation or during memory allocation.");
    }

    gchar *msg = NULL;

    if (header_metadata->algo_mode == GCRY_CIPHER_MODE_GCM) {
        /* GCM: file is [Metadata][Encrypted Data][GCM Tag (16 bytes)] */
        goffset enc_data_size = file_size - (goffset)sizeof (Metadata) - TAG_SIZE;
        if (enc_data_size <= 0) {
            crypto_keys_cleanup (decryption_keys);
            gfile_cleanup (in_file, out_file);
            gstream_cleanup (in_stream, out_stream);
            g_free (output_file_path);
            g_free (header_metadata);
            return g_strdup ("The selected file is too small to be valid.");
        }

        /* Read stored GCM tag from end of file */
        guchar stored_tag[TAG_SIZE];
        if (!g_seekable_seek (G_SEEKABLE (in_stream), file_size - TAG_SIZE, G_SEEK_SET, NULL, &err)) {
            err_msg = g_strdup (err->message);
            g_clear_error (&err);
            crypto_keys_cleanup (decryption_keys);
            gfile_cleanup (in_file, out_file);
            gstream_cleanup (in_stream, out_stream);
            g_free (output_file_path);
            g_free (header_metadata);
            return err_msg;
        }
        rw_len = g_input_stream_read (G_INPUT_STREAM (in_stream), stored_tag, TAG_SIZE, NULL, &err);
        if (rw_len != TAG_SIZE) {
            crypto_keys_cleanup (decryption_keys);
            gfile_cleanup (in_file, out_file);
            gstream_cleanup (in_stream, out_stream);
            g_free (output_file_path);
            g_free (header_metadata);
            return g_strdup ("Failed to read GCM authentication tag.");
        }

        /* Seek back to encrypted data start */
        if (!g_seekable_seek (G_SEEKABLE (in_stream), sizeof (Metadata), G_SEEK_SET, NULL, &err)) {
            err_msg = g_strdup (err->message);
            g_clear_error (&err);
            crypto_keys_cleanup (decryption_keys);
            gfile_cleanup (in_file, out_file);
            gstream_cleanup (in_stream, out_stream);
            g_free (output_file_path);
            g_free (header_metadata);
            return err_msg;
        }

        msg = decrypt_gcm (header_metadata, decryption_keys, in_stream, enc_data_size, stored_tag, out_stream);
        if (msg != NULL) {
            /* Authentication failed — delete partial output */
            gchar *out_path = g_file_get_path (out_file);
            g_unlink (out_path);
            g_free (out_path);
        }
    } else {
        /* CBC/CTR: file is [Metadata][Encrypted Data][HMAC (64 bytes)] */
        if (file_size < (goffset)(sizeof (Metadata) + SHA512_DIGEST_SIZE)) {
            crypto_keys_cleanup (decryption_keys);
            gfile_cleanup (in_file, out_file);
            gstream_cleanup (in_stream, out_stream);
            g_free (output_file_path);
            g_free (header_metadata);
            return g_strdup ("The selected file is too small to be valid.");
        }

        guchar *original_hmac = g_malloc0 (SHA512_DIGEST_SIZE);
        if (!g_seekable_seek (G_SEEKABLE (in_stream), file_size - SHA512_DIGEST_SIZE, G_SEEK_SET, NULL, &err)) {
            err_msg = g_strdup (err->message);
            g_clear_error (&err);
            crypto_keys_cleanup (decryption_keys);
            gfile_cleanup (in_file, out_file);
            gstream_cleanup (in_stream, out_stream);
            data_cleanup (header_metadata, output_file_path, original_hmac);
            return err_msg;
        }
        rw_len = g_input_stream_read (G_INPUT_STREAM (in_stream), original_hmac, SHA512_DIGEST_SIZE, NULL, &err);
        if (rw_len == -1) {
            err_msg = g_strdup (err->message);
            g_clear_error (&err);
            crypto_keys_cleanup (decryption_keys);
            gfile_cleanup (in_file, out_file);
            gstream_cleanup (in_stream, out_stream);
            data_cleanup (header_metadata, output_file_path, original_hmac);
            return err_msg;
        }

        if (!g_seekable_seek (G_SEEKABLE (in_stream), 0, G_SEEK_SET, NULL, &err)) {
            err_msg = g_strdup (err->message);
            g_clear_error (&err);
            crypto_keys_cleanup (decryption_keys);
            gfile_cleanup (in_file, out_file);
            gstream_cleanup (in_stream, out_stream);
            data_cleanup (header_metadata, output_file_path, original_hmac);
            return err_msg;
        }
        GFile *file_encrypted_data = get_g_file_with_encrypted_data (in_stream, file_size);
        if (file_encrypted_data == NULL) {
            crypto_keys_cleanup (decryption_keys);
            gfile_cleanup (in_file, out_file);
            gstream_cleanup (in_stream, out_stream);
            data_cleanup (header_metadata, output_file_path, original_hmac);
            return g_strdup ("Couldn't get the encrypted data from the file.");
        }

        if (!compare_hmac (decryption_keys->hmac_key, original_hmac, file_encrypted_data)) {
            g_object_unref (file_encrypted_data);
            crypto_keys_cleanup (decryption_keys);
            gfile_cleanup (in_file, out_file);
            gstream_cleanup (in_stream, out_stream);
            data_cleanup (header_metadata, output_file_path, original_hmac);
            return g_strdup ("HMAC differs from the one stored inside the file.\nEither the password is wrong or the file has been corrupted.");
        }

        msg = decrypt (header_metadata, decryption_keys, file_encrypted_data, file_size - sizeof (Metadata) - SHA512_DIGEST_SIZE, out_stream);

        gchar *tmp_path = g_file_get_path (file_encrypted_data);
        g_unlink (tmp_path);
        g_free (tmp_path);

        g_object_unref (file_encrypted_data);
        g_free (original_hmac);
    }

    crypto_keys_cleanup (decryption_keys);
    gfile_cleanup (in_file, out_file);
    gstream_cleanup (in_stream, out_stream);
    g_free (output_file_path);
    g_free (header_metadata);
    return msg;
}


static GFile *
get_g_file_with_encrypted_data (GFileInputStream *in_stream,
                                goffset           file_size)
{
    GError *err = NULL;
    GFileIOStream *ostream;
    gssize read_len;
    guchar *buf;
    goffset len_file_data = file_size - SHA512_DIGEST_SIZE;
    gsize done_size = 0;

    GFile *tmp_encrypted_file = g_file_new_tmp (NULL, &ostream, &err);
    if (tmp_encrypted_file == NULL) {
        g_printerr ("%s\n", err->message);
        return NULL;
    }

    GFileOutputStream *out_enc_stream = g_file_append_to (tmp_encrypted_file, G_FILE_CREATE_NONE, NULL, &err);
    if (out_enc_stream == NULL) {
        g_printerr ("%s\n", err->message);
        return NULL;
    }

    if (len_file_data < FILE_BUFFER) {
        buf = g_malloc0 ((gsize)len_file_data);
        g_input_stream_read (G_INPUT_STREAM (in_stream), buf, (gsize)len_file_data, NULL, &err);
        g_output_stream_write (G_OUTPUT_STREAM (out_enc_stream), buf, (gsize)len_file_data, NULL, &err);
    } else {
        buf = g_malloc (FILE_BUFFER);
        while (done_size < len_file_data) {
            if ((len_file_data - done_size) > FILE_BUFFER) {
                read_len = g_input_stream_read (G_INPUT_STREAM (in_stream), buf, FILE_BUFFER, NULL, &err);
            } else {
                read_len = g_input_stream_read (G_INPUT_STREAM (in_stream), buf, len_file_data - done_size, NULL, &err);
            }
            if (read_len == -1) {
                g_printerr ("%s\n", err->message);
                return NULL;
            }
            g_output_stream_write (G_OUTPUT_STREAM (out_enc_stream), buf, (gsize)read_len, NULL, &err);
            done_size += read_len;
            memset (buf, 0, FILE_BUFFER);
        }
    }

    gstream_cleanup (NULL, out_enc_stream);
    g_free (buf);

    return tmp_encrypted_file;
}


static gboolean
compare_hmac (guchar *hmac_key,
              guchar *original_hmac,
              GFile  *encrypted_data)
{
    gchar *path = g_file_get_path (encrypted_data);

    gboolean result = (calculate_hmac (path, hmac_key, original_hmac) != HMAC_MISMATCH);
    g_free (path);
    return result;
}


gpointer
decrypt (Metadata          *header_metadata,
         CryptoKeys        *dec_keys,
         GFile             *enc_data,
         goffset            enc_data_size,
         GFileOutputStream *ostream)
{
    gcry_cipher_hd_t hd;
    gcry_error_t gcry_err = gcry_cipher_open (&hd, header_metadata->algo, header_metadata->algo_mode, 0);
    if (gcry_err) {
        return g_strdup ("Failed to initialize cipher");
    }
    gcry_cipher_setkey (hd, dec_keys->crypto_key, gcry_cipher_get_algo_keylen (header_metadata->algo));

    if (header_metadata->algo_mode == GCRY_CIPHER_MODE_CBC) {
        gcry_cipher_setiv (hd, header_metadata->iv, header_metadata->iv_size);
    } else {
        gcry_cipher_setctr (hd, header_metadata->iv, header_metadata->iv_size);
    }

    GError *err = NULL;
    gchar *err_msg = NULL;

    GFileInputStream *in_stream = g_file_read (enc_data, NULL, &err);
    if (err != NULL) {
        err_msg = g_strdup (err->message);
        g_clear_error (&err);
        return err_msg;
    }
    if (!g_seekable_seek (G_SEEKABLE (in_stream), sizeof (Metadata), G_SEEK_SET, NULL, &err)) {
        err_msg = g_strdup (err->message);
        g_clear_error (&err);
        return err_msg;
    }

    guchar *enc_buf = g_try_malloc0 (FILE_BUFFER);
    guchar *dec_buf = g_try_malloc0 (FILE_BUFFER);

    if (enc_buf == NULL || dec_buf == NULL) {
        if (enc_buf != NULL) g_free (enc_buf);
        if (dec_buf != NULL) g_free (dec_buf);
        return g_strdup ("Error during memory allocation.");
    }

    goffset done_size = 0;
    gssize read_len;

    while (done_size < enc_data_size) {
        if ((enc_data_size - done_size) <= FILE_BUFFER) {
            read_len = g_input_stream_read (G_INPUT_STREAM (in_stream), enc_buf, (gsize)enc_data_size - done_size, NULL, &err);
            gcry_cipher_decrypt (hd, dec_buf, (gsize)read_len, enc_buf, (gsize)read_len);
            g_output_stream_write (G_OUTPUT_STREAM (ostream), dec_buf, (gsize)read_len - header_metadata->padding_value, NULL, &err);
        } else {
            read_len = g_input_stream_read (G_INPUT_STREAM (in_stream), enc_buf, FILE_BUFFER, NULL, &err);
            gcry_cipher_decrypt (hd, dec_buf, (gsize)read_len, enc_buf, (gsize)read_len);
            g_output_stream_write (G_OUTPUT_STREAM (ostream), dec_buf, (gsize)read_len, NULL, &err);
        }

        explicit_bzero (dec_buf, FILE_BUFFER);
        explicit_bzero (enc_buf, FILE_BUFFER);

        done_size += read_len;
    }

    gcry_cipher_close (hd);

    g_free (enc_buf);
    g_free (dec_buf);

    g_input_stream_close (G_INPUT_STREAM (in_stream), NULL, NULL);

    g_object_unref (in_stream);

    return NULL;
}


static gpointer
decrypt_gcm (Metadata          *header_metadata,
             CryptoKeys        *dec_keys,
             GFileInputStream  *in_stream,
             goffset            enc_data_size,
             const guchar      *stored_tag,
             GFileOutputStream *ostream)
{
    gcry_cipher_hd_t hd;
    gcry_error_t gcry_err = gcry_cipher_open (&hd, header_metadata->algo, GCRY_CIPHER_MODE_GCM, 0);
    if (gcry_err) {
        return g_strdup ("Failed to initialize cipher");
    }
    gcry_cipher_setkey (hd, dec_keys->crypto_key, gcry_cipher_get_algo_keylen (header_metadata->algo));
    gcry_cipher_setiv (hd, header_metadata->iv, header_metadata->iv_size);

    guchar *enc_buf = g_try_malloc0 (FILE_BUFFER);
    guchar *dec_buf = g_try_malloc0 (FILE_BUFFER);

    if (enc_buf == NULL || dec_buf == NULL) {
        if (enc_buf != NULL) g_free (enc_buf);
        if (dec_buf != NULL) g_free (dec_buf);
        gcry_cipher_close (hd);
        return g_strdup ("Error during memory allocation.");
    }

    GError *err = NULL;
    goffset done_size = 0;
    gssize read_len;

    while (done_size < enc_data_size) {
        goffset remaining = enc_data_size - done_size;
        gboolean is_last = (remaining <= FILE_BUFFER);

        if (is_last) {
            read_len = g_input_stream_read (G_INPUT_STREAM (in_stream), enc_buf, (gsize)remaining, NULL, &err);
        } else {
            read_len = g_input_stream_read (G_INPUT_STREAM (in_stream), enc_buf, FILE_BUFFER, NULL, &err);
        }
        if (read_len == -1) {
            g_free (enc_buf);
            g_free (dec_buf);
            gcry_cipher_close (hd);
            gchar *err_msg = g_strdup (err->message);
            g_clear_error (&err);
            return err_msg;
        }

        if (is_last) {
            gcry_cipher_final (hd);
        }

        gcry_cipher_decrypt (hd, dec_buf, (gsize)read_len, enc_buf, (gsize)read_len);
        g_output_stream_write (G_OUTPUT_STREAM (ostream), dec_buf, (gsize)read_len, NULL, &err);

        explicit_bzero (dec_buf, FILE_BUFFER);
        explicit_bzero (enc_buf, FILE_BUFFER);

        done_size += read_len;
    }

    /* Verify GCM authentication tag */
    gcry_err = gcry_cipher_checktag (hd, stored_tag, TAG_SIZE);
    gcry_cipher_close (hd);

    g_free (enc_buf);
    g_free (dec_buf);

    if (gcry_err) {
        return g_strdup ("GCM authentication failed.\nEither the password is wrong or the file has been corrupted.");
    }

    return NULL;
}
