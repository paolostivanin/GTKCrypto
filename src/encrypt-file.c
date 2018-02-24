#include <gtk/gtk.h>
#include <gcrypt.h>
#include "gtkcrypto.h"
#include "hash.h"
#include "crypt-common.h"

static void set_algo_and_mode (Metadata *header_metadata, const gchar *, const gchar *);

static void set_number_of_blocks_and_padding_bytes (goffset, gsize, gint64 *, gint *);

static gchar *encrypt_using_cbc_mode (Metadata *metadata, gcry_cipher_hd_t *, goffset filesize, gint64 num_of_blocks, gint num_of_padding_bytes, gsize block_length, GFileInputStream *, GFileOutputStream *);

static gchar *encrypt_using_ctr_mode (Metadata *header_metadata, gcry_cipher_hd_t *, goffset file_size, GFileInputStream *, GFileOutputStream *);


gpointer
encrypt_file (const gchar *input_file_path, const gchar *pwd, const gchar *algo, const gchar *algo_mode)
{
    Metadata *header_metadata = g_new0 (Metadata, 1);
    CryptoKeys *encryption_keys = g_new0 (CryptoKeys, 1);

    set_algo_and_mode (header_metadata, algo, algo_mode);
    gsize algo_key_len = gcry_cipher_get_algo_keylen (header_metadata->algo);
    gsize algo_blk_len = gcry_cipher_get_algo_blklen (header_metadata->algo);

    header_metadata->iv_size = algo_blk_len;  // iv must be the same size as the block size

    gcry_create_nonce (header_metadata->iv, header_metadata->iv_size);
    gcry_create_nonce (header_metadata->salt, KDF_SALT_SIZE);

    if (!setup_keys (pwd, algo_key_len, header_metadata, encryption_keys)) {
        multiple_free (2, (gpointer) &encryption_keys, (gpointer) &header_metadata);
        return g_strdup ("Couldn't setup the encryption keys, exiting...");
    }

    goffset filesize = get_file_size (input_file_path);

    GError *err = NULL;
    gchar *err_msg = NULL;

    GFile *in_file = g_file_new_for_path (input_file_path);
    GFileInputStream *in_stream = g_file_read (in_file, NULL, &err);
    if (err != NULL) {
        multiple_gcry_free (3, (gpointer) &encryption_keys->derived_key, (gpointer) &encryption_keys->crypto_key,
                            (gpointer) &encryption_keys->hmac_key);
        multiple_free (2, (gpointer) &encryption_keys, (gpointer) &header_metadata);
        g_object_unref (in_file);
        err_msg = g_strdup (err->message);
        g_clear_error (&err);
        return err_msg;
    }

    gchar *output_file_path = g_strconcat (input_file_path, ".enc", NULL);
    GFile *out_file = g_file_new_for_path (output_file_path);
    GFileOutputStream *out_stream = g_file_append_to (out_file, G_FILE_CREATE_REPLACE_DESTINATION, NULL, &err);
    if (err != NULL) {
        multiple_gcry_free (3, (gpointer) &encryption_keys->derived_key, (gpointer) &encryption_keys->crypto_key,
                            (gpointer) &encryption_keys->hmac_key);
        multiple_free (3, (gpointer) &encryption_keys, (gpointer) &header_metadata, (gpointer) &output_file_path);
        multiple_unref (3, (gpointer) &in_file, (gpointer) &out_file, (gpointer) &in_stream);
        g_input_stream_close (G_INPUT_STREAM (in_stream), NULL, NULL);
        err_msg = g_strdup (err->message);
        g_clear_error (&err);
        return err_msg;
    }

    gcry_cipher_hd_t hd;
    gcry_cipher_open (&hd, header_metadata->algo, header_metadata->algo_mode, 0);
    gcry_cipher_setkey (hd, encryption_keys->crypto_key, algo_key_len);

    gint64 number_of_blocks;
    gint number_of_padding_bytes;
    gchar *ret_msg;
    if (header_metadata->algo_mode == GCRY_CIPHER_MODE_CBC) {
        set_number_of_blocks_and_padding_bytes (filesize, algo_blk_len, &number_of_blocks, &number_of_padding_bytes);
        gcry_cipher_setiv (hd, header_metadata->iv, header_metadata->iv_size);
        ret_msg = encrypt_using_cbc_mode (header_metadata, &hd, filesize, number_of_blocks, number_of_padding_bytes, algo_blk_len, in_stream, out_stream);
    } else {
        gcry_cipher_setctr (hd, header_metadata->iv, header_metadata->iv_size);
        ret_msg = encrypt_using_ctr_mode (header_metadata, &hd, filesize, in_stream, out_stream);
    }
    if (ret_msg != NULL) {
        multiple_gcry_free (3, (gpointer) &encryption_keys->derived_key, (gpointer) &encryption_keys->crypto_key,
                            (gpointer) &encryption_keys->hmac_key);
        multiple_free (3, (gpointer) &encryption_keys, (gpointer) &header_metadata, (gpointer) &output_file_path);
        multiple_unref (4, (gpointer) &in_file, (gpointer) &out_file, (gpointer) &in_stream,
                        (gpointer) &out_stream);
        g_input_stream_close (G_INPUT_STREAM (in_stream), NULL, NULL);
        g_output_stream_close (G_OUTPUT_STREAM (out_stream), NULL, NULL);

        return g_strdup (ret_msg);

    }

    gcry_cipher_close (hd);

    guchar *hmac = calculate_hmac (output_file_path, encryption_keys->hmac_key, NULL);
    gssize written_bytes = g_output_stream_write (G_OUTPUT_STREAM (out_stream), hmac, SHA512_DIGEST_SIZE, NULL, &err);
    if (written_bytes == -1) {
        multiple_gcry_free (3, (gpointer) &encryption_keys->derived_key, (gpointer) &encryption_keys->crypto_key,
                            (gpointer) &encryption_keys->hmac_key);
        multiple_free (4, (gpointer) &encryption_keys, (gpointer) &header_metadata, (gpointer) &output_file_path,
                       (gpointer) &hmac);
        multiple_unref (4, (gpointer) &in_file, (gpointer) &out_file, (gpointer) &in_stream,
                        (gpointer) &out_stream);
        g_output_stream_close (G_OUTPUT_STREAM (out_stream), NULL, NULL);
        err_msg = g_strdup (err->message);
        g_clear_error (&err);
        return err_msg;
    }

    g_input_stream_close (G_INPUT_STREAM (in_stream), NULL, NULL);
    g_output_stream_close (G_OUTPUT_STREAM (out_stream), NULL, NULL);

    multiple_gcry_free (3, (gpointer) &encryption_keys->derived_key, (gpointer) &encryption_keys->crypto_key,
                        (gpointer) &encryption_keys->hmac_key);

    multiple_free (4, (gpointer) &output_file_path, (gpointer) &encryption_keys, (gpointer) &header_metadata,
                   (gpointer) &hmac);

    multiple_unref (4, (gpointer) &in_file, (gpointer) &out_file, (gpointer) &in_stream,
                    (gpointer) &out_stream);

    return NULL;
}


static void
set_algo_and_mode (Metadata *header_metadata, const gchar *algo, const gchar *algo_mode)
{
    if (g_strcmp0 (algo, "AES256") == 0) {
        header_metadata->algo = GCRY_CIPHER_AES256;
    } else if (g_strcmp0 (algo, "BLOWFISH") == 0) {
        header_metadata->algo = GCRY_CIPHER_BLOWFISH;
    } else if (g_strcmp0 (algo, "CAMELLIA256") == 0) {
        header_metadata->algo = GCRY_CIPHER_CAMELLIA256;
    } else if (g_strcmp0 (algo, "CAST5") == 0) {
        header_metadata->algo = GCRY_CIPHER_CAST5;
    } else if (g_strcmp0 (algo, "SERPENT256") == 0) {
        header_metadata->algo = GCRY_CIPHER_SERPENT256;
    } else {
        header_metadata->algo = GCRY_CIPHER_TWOFISH;
    }

    if (g_strcmp0 (algo_mode, "CBC") == 0) {
        header_metadata->algo_mode = GCRY_CIPHER_MODE_CBC;
    } else {
        header_metadata->algo_mode = GCRY_CIPHER_MODE_CTR;
    }
}


static void
set_number_of_blocks_and_padding_bytes (goffset file_size, gsize block_length, gint64 *num_of_blocks, gint *num_of_padding_bytes)
{
    gint64 file_blocks = file_size / block_length;

    gint spare_bytes = (gint) (file_size % block_length);  // number of bytes left which didn't filled up a block

    if (spare_bytes > 0) {
        *num_of_blocks = file_blocks + 1;
        *num_of_padding_bytes = (gint) (block_length - spare_bytes);
    } else {
        *num_of_blocks = file_blocks;
        *num_of_padding_bytes = spare_bytes;
    }
}


static gchar *
encrypt_using_cbc_mode (Metadata *header_metadata, gcry_cipher_hd_t *hd, goffset file_size, gint64 num_of_blocks, gint num_of_padding_bytes,
                        gsize block_length, GFileInputStream *in_stream, GFileOutputStream *out_stream)
{
    GError *err = NULL;
    gchar *err_msg = NULL;
    guchar padding[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    header_metadata->padding_value = padding[num_of_padding_bytes];

    guchar *buffer = g_try_malloc0 ((gsize)(file_size < FILE_BUFFER ? file_size : FILE_BUFFER));
    guchar *enc_buffer = g_try_malloc0 ((gsize)(file_size < FILE_BUFFER ? file_size : FILE_BUFFER));
    if (buffer == NULL || enc_buffer == NULL) {
        return g_strdup ("Couldn't allocate memory");
    }

    if (g_output_stream_write (G_OUTPUT_STREAM (out_stream), header_metadata, sizeof (Metadata), NULL, &err) == -1) {
        multiple_free (2, (gpointer) &buffer, (gpointer) &enc_buffer);
        err_msg = g_strdup (err->message);
        g_clear_error (&err);
        return err_msg;
    }

    gssize read_len;
    gint64 done_blocks = 0;

    while (done_blocks < num_of_blocks) {
        goffset remaining_bytes = ((num_of_blocks - done_blocks) * block_length);
        if (remaining_bytes > FILE_BUFFER) {
            read_len = g_input_stream_read (G_INPUT_STREAM (in_stream), buffer, FILE_BUFFER, NULL, &err);
            done_blocks += (read_len / block_length);
        } else {
            read_len = g_input_stream_read (G_INPUT_STREAM (in_stream), buffer, (gsize)remaining_bytes, NULL, &err);
            for (gsize j = (gsize)read_len, i = (block_length - num_of_padding_bytes); i < block_length; i++) {
                buffer[j] = header_metadata->padding_value;
                j++;
            }
            done_blocks += ((read_len + num_of_padding_bytes) / block_length);
        }
        if (read_len == -1) {
            multiple_free (2, (gpointer) &buffer, (gpointer) &enc_buffer);
            err_msg = g_strdup (err->message);
            g_clear_error (&err);
            return err_msg;
        }

        gsize num_of_bytes_to_encrypt = (gsize)(remaining_bytes < FILE_BUFFER ? remaining_bytes : FILE_BUFFER);
        gcry_cipher_encrypt (*hd, enc_buffer, num_of_bytes_to_encrypt, buffer, num_of_bytes_to_encrypt);
        if (g_output_stream_write (G_OUTPUT_STREAM (out_stream), enc_buffer, num_of_bytes_to_encrypt, NULL, &err) != num_of_bytes_to_encrypt) {
            multiple_free (2, (gpointer) &buffer, (gpointer) &enc_buffer);
            return g_strdup ("Error while trying to write encrypted data to the output file");
        }

        memset (buffer, 0, num_of_bytes_to_encrypt);
        memset (enc_buffer, 0, num_of_bytes_to_encrypt);
    }

    multiple_free (2, (gpointer) &buffer, (gpointer) &enc_buffer);

    return NULL;
}


static gchar *
encrypt_using_ctr_mode (Metadata *header_metadata, gcry_cipher_hd_t *hd, goffset file_size,
                        GFileInputStream *in_stream, GFileOutputStream *out_stream)
{
    GError *err = NULL;
    gchar *err_msg = NULL;

    if (g_output_stream_write (G_OUTPUT_STREAM (out_stream), header_metadata, sizeof (Metadata), NULL, &err) == -1) {
        err_msg = g_strdup (err->message);
        g_clear_error (&err);
        return err_msg;
    }

    guchar *buffer = g_try_malloc0 ((gsize)(file_size < FILE_BUFFER ? file_size : FILE_BUFFER));
    guchar *enc_buffer = g_try_malloc0 ((gsize)(file_size < FILE_BUFFER ? file_size : FILE_BUFFER));

    if (buffer == NULL || enc_buffer == NULL) {
        return g_strdup ("Couldn't allocate memory");
    }

    goffset done_size = 0;
    gssize read_len;

    while (done_size < file_size) {
        if ((file_size - done_size) > FILE_BUFFER) {
            read_len = g_input_stream_read (G_INPUT_STREAM (in_stream), buffer, FILE_BUFFER, NULL, &err);
        } else {
            read_len = g_input_stream_read (G_INPUT_STREAM (in_stream), buffer, (gsize)file_size - done_size, NULL, &err);
        }
        if (read_len == -1) {
            multiple_free (2, (gpointer) &buffer, (gpointer) &enc_buffer);
            err_msg = g_strdup (err->message);
            g_clear_error (&err);
            return err_msg;
        }

        gcry_cipher_encrypt (*hd, enc_buffer, (gsize)read_len, buffer, (gsize)read_len);
        if (g_output_stream_write (G_OUTPUT_STREAM (out_stream), enc_buffer, (gsize)read_len, NULL, &err) == -1) {
            multiple_free (2, (gpointer) &buffer, (gpointer) &enc_buffer);
            err_msg = g_strdup (err->message);
            g_clear_error (&err);
            return err_msg;
        }

        memset (buffer, 0, (gsize)(file_size < FILE_BUFFER ? file_size : FILE_BUFFER));
        memset (enc_buffer, 0, (gsize)(file_size < FILE_BUFFER ? file_size : FILE_BUFFER));

        done_size += read_len;
    }

    multiple_free (2, (gpointer) &buffer, (gpointer) &enc_buffer);

    return NULL;
}