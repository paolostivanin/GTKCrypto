#include <gtk/gtk.h>
#include <gcrypt.h>
#include "gtkcrypto.h"
#include "hash.h"

#define FILE_BUFFER 67108864 // 64 MiB
#define ROUNDS 50000
#define SALT_SIZE 32
#define HMAC_KEY_SIZE 32

typedef struct header_metadata_t {
    guint8 *iv;
    gsize iv_size;
    guint8 salt[SALT_SIZE];
    gint algo;
    gint algo_mode;
    guint8 padding_value;
} Metadata;

typedef struct key_t {
    guchar *derived_key;
    guchar *crypto_key;
    guchar *hmac_key;
} EncryptionKeys;

static void set_algo_and_mode (Metadata *, const gchar *, const gchar *);

static gboolean setup_keys (const gchar *, gsize, Metadata *, EncryptionKeys *);

static void set_number_of_blocks_and_padding_bytes (goffset, gsize, gint64 *, gint *);

static void encrypt_using_cbc_mode (Metadata *, gcry_cipher_hd_t, gint64, gint, gsize, GFileInputStream *, GFileOutputStream *);


void
encrypt_file (const gchar *input_file_path, const gchar *pwd, const gchar *algo, const gchar *algo_mode)
{
    // TODO check what happens if the .enc file already exists
    Metadata *header_metadata = g_new0 (Metadata, 1);
    EncryptionKeys *encryption_keys = g_new0 (EncryptionKeys, 1);

    set_algo_and_mode (header_metadata, algo, algo_mode);
    gsize algo_key_len = gcry_cipher_get_algo_keylen (header_metadata->algo);
    gsize algo_blk_len = gcry_cipher_get_algo_blklen (header_metadata->algo);

    header_metadata->iv_size = algo_blk_len;  // iv must be the same size as the block size
    header_metadata->iv = (guint8 *) gcry_malloc (header_metadata->iv_size);

    gcry_create_nonce (header_metadata->iv, header_metadata->iv_size);
    gcry_create_nonce (header_metadata->salt, SALT_SIZE);

    if (!setup_keys (pwd, algo_key_len, header_metadata, encryption_keys)) {
        // TODO
        return;
    }

    goffset filesize = get_file_size (input_file_path);

    GError *err = NULL;

    GFile *in_file = g_file_new_for_path (input_file_path);
    GFileInputStream *in_stream = g_file_read (in_file, NULL, &err);
    if (err != NULL) {
        g_printerr ("%s\n", err->message);
        // TODO
        return;
    }

    gchar *output_file_path = g_strconcat (input_file_path, ".enc", NULL);
    GFile *out_file = g_file_new_for_path (output_file_path);
    GFileOutputStream *out_stream = g_file_append_to (out_file, G_FILE_CREATE_NONE, NULL, &err);
    if (err != NULL) {
        g_printerr ("%s\n", err->message);
        // TODO
        return;
    }

    gcry_cipher_hd_t hd;
    gcry_cipher_open (&hd, header_metadata->algo, header_metadata->algo_mode, 0);
    gcry_cipher_setkey (hd, encryption_keys->crypto_key, algo_key_len);

    gint64 number_of_blocks;
    gint number_of_padding_bytes;
    if (header_metadata->algo_mode == GCRY_CIPHER_MODE_CBC) {
        set_number_of_blocks_and_padding_bytes (filesize, algo_blk_len, &number_of_blocks, &number_of_padding_bytes);
        gcry_cipher_setiv (hd, header_metadata->iv, header_metadata->iv_size);
        encrypt_using_cbc_mode (header_metadata, hd, number_of_blocks, number_of_padding_bytes, algo_blk_len, in_stream, out_stream);
    }
    else {
        gcry_cipher_setctr (hd, header_metadata->iv, header_metadata->iv_size);
        //encrypt_using_ctr_mode ();
    }

    gcry_cipher_close (hd);

    guchar *hmac = calculate_hmac (output_file_path, encryption_keys->hmac_key, HMAC_KEY_SIZE);
    // TODO wirte hmac

    multiple_gcry_free (4, (gpointer *) &encryption_keys->derived_key,
                        (gpointer *) &encryption_keys->crypto_key,
                        (gpointer *) &encryption_keys->hmac_key,
                        (gpointer *) &header_metadata->iv);

    multiple_free (3, (gpointer *) &output_file_path,
                   (gpointer *) &encryption_keys,
                   (gpointer *) &header_metadata);

    g_object_unref (in_file);
    g_object_unref (out_file);
    g_object_unref (in_stream);
    g_object_unref (out_stream);
}


static void
set_algo_and_mode (Metadata *header_metadata, const gchar *algo, const gchar *algo_mode)
{
    if (g_strcmp0 (algo, "AES256") == 0) {
        header_metadata->algo = GCRY_CIPHER_AES256;
    }
    else if (g_strcmp0 (algo, "BLOWFISH") == 0) {
        header_metadata->algo = GCRY_CIPHER_BLOWFISH;
    }
    else if (g_strcmp0 (algo, "CAMELLIA256") == 0) {
        header_metadata->algo = GCRY_CIPHER_CAMELLIA256;
    }
    else if (g_strcmp0 (algo, "CAST5") == 0) {
        header_metadata->algo = GCRY_CIPHER_CAST5;
    }
    else if (g_strcmp0 (algo, "SERPENT256") == 0) {
        header_metadata->algo = GCRY_CIPHER_SERPENT256;
    }
    else {
        header_metadata->algo = GCRY_CIPHER_TWOFISH;
    }

    if (g_strcmp0 (algo_mode, "CBC") == 0) {
        header_metadata->algo_mode = GCRY_CIPHER_MODE_CBC;
    }
    else {
        header_metadata->algo_mode = GCRY_CIPHER_MODE_CTR;
    }
}


static gboolean
setup_keys (const gchar *pwd, gsize algo_key_len, Metadata *header_metadata, EncryptionKeys *encryption_keys)
{
    encryption_keys->derived_key = gcry_malloc_secure (64);
    if (encryption_keys->derived_key == NULL) {
        return FALSE;
    }

    if (gcry_kdf_derive (pwd, (gsize) g_utf8_strlen (pwd, -1) + 1, GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                         header_metadata->salt, SALT_SIZE, ROUNDS, 64, encryption_keys->derived_key) != 0) {
        return FALSE;
    }

    encryption_keys->crypto_key = gcry_malloc_secure (algo_key_len);
    if (encryption_keys->crypto_key == NULL) {
        return FALSE;
    }
    memcpy (encryption_keys->crypto_key, encryption_keys->derived_key, algo_key_len);

    encryption_keys->hmac_key = gcry_malloc_secure (HMAC_KEY_SIZE);
    if (encryption_keys->hmac_key == NULL) {
        return FALSE;
    }
    memcpy (encryption_keys->hmac_key, encryption_keys->derived_key + algo_key_len, HMAC_KEY_SIZE);

    return TRUE;
}


static void
set_number_of_blocks_and_padding_bytes (goffset file_size, gsize block_length, gint64 *num_of_blocks, gint *num_of_padding_bytes)
{
    gint64 file_blocks = file_size / block_length;

    gint spare_bytes = (gint) (file_size % block_length);  // number of bytes left which didn't filled up a block

    if (spare_bytes > 0) {
        *num_of_blocks = file_blocks + 1;
        *num_of_padding_bytes = (gint) (block_length - spare_bytes);
    }
    else {
        *num_of_blocks = file_blocks;
        *num_of_padding_bytes = spare_bytes;
    }
}


static void
encrypt_using_cbc_mode (Metadata *header_metadata, gcry_cipher_hd_t hd, gint64 num_of_blocks, gint num_of_padding_bytes,
                        gsize block_length, GFileInputStream *in_stream, GFileOutputStream *out_stream)
{
    // TODO test speed by increasing encrypt size from block_size to ...
    // TODO hmac
    GError *err = NULL;
    guchar *buffer = g_malloc0 (block_length);
    guchar *enc_buffer = g_malloc0 (block_length);
    guchar padding[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    header_metadata->padding_value = padding[num_of_padding_bytes];

    gssize rw_len;

    g_output_stream_write (G_OUTPUT_STREAM (out_stream), header_metadata, sizeof (Metadata), NULL, &err);
    if (err != NULL) {
        g_printerr ("%s\n", err->message);
        // TODO do something
        return;
    }

    gsize i;
    gint64 done_blocks = 0;
    while (done_blocks < num_of_blocks) {
        rw_len = g_input_stream_read (G_INPUT_STREAM (in_stream), buffer, block_length, NULL, &err);
        if (rw_len == -1) {
            g_printerr ("%s\n", err->message);
            // TODO do something
            return;
        }
        if (rw_len < block_length) {
            for (i = (block_length - num_of_padding_bytes); i < block_length; i++) {
                buffer[i] = header_metadata->padding_value;
            }
        }
        gcry_cipher_encrypt (hd, enc_buffer, block_length, buffer, block_length);
        rw_len = g_output_stream_write (G_OUTPUT_STREAM (out_stream), enc_buffer, block_length, NULL, &err);
        if (rw_len != block_length) {
            g_printerr ("%s\n", err->message);
            // TODO do something
            return;
        }
        memset (buffer, 0, block_length);
        memset (enc_buffer, 0, block_length);

        done_blocks++;
    }

    g_output_stream_close (G_OUTPUT_STREAM (out_stream), NULL, NULL);
    g_input_stream_close (G_INPUT_STREAM (in_stream), NULL, NULL);
}