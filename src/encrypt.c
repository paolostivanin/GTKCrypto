#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include "gtkcrypto.h"

#define FILE_BUFFER 67108864 // 64 MiB
#define ROUNDS 50000
#define IV_SIZE 16
#define SALT_SIZE 32
#define HMAC_KEY_SIZE 32

typedef struct header_metadata_t {
    guint8 iv[IV_SIZE];
    guint8 salt[SALT_SIZE];
    gint algo;
    gint algo_mode;
} Metadata;

typedef struct key_t {
    guchar *derived_key;
    guchar *crypto_key;
    guchar *hmac_key;
} EncryptionKeys;

static void set_algo_and_mode (Metadata *, const gchar *, const gchar *);

static gboolean setup_keys (const gchar *, gsize, Metadata *, EncryptionKeys *);


void
encrypt_file (const gchar *filename, const gchar *pwd, const gchar *algo, const gchar *algo_mode)
{
    Metadata *header_metadata = g_new0 (Metadata, 1);
    EncryptionKeys *encryption_keys = g_new0 (EncryptionKeys, 1);

    set_algo_and_mode (header_metadata, algo, algo_mode);
    gsize algo_key_len = gcry_cipher_get_algo_keylen (header_metadata->algo);
    gsize algo_blk_len = gcry_cipher_get_algo_blklen (header_metadata->algo);

    gcry_create_nonce (header_metadata->iv, IV_SIZE);
    gcry_create_nonce (header_metadata->salt, SALT_SIZE);

    if (!setup_keys (pwd, algo_key_len, header_metadata, encryption_keys)) {
        // TODO
        return;
    }

    goffset filesize = get_file_size (filename);

    FILE *fp_in = g_fopen (filename, "r");
    if (fp_in == NULL) {
        //TODO
        return;
    }

    gchar *out_filename = g_strconcat (filename, ".enc", NULL);
    FILE *fp_out = g_fopen (out_filename, "w");
    if (fp_out == NULL) {
        // TODO
        return;
    }

    gcry_cipher_hd_t hd;
    gcry_cipher_open (&hd, header_metadata->algo, header_metadata->algo_mode, 0);

    /* if CBC number of blocks (blowfish and cast5 have 8 bytes blocks, all the others 16 bytes...
     * if CTR no problem
     */

    gcry_cipher_close (hd);

    fclose (fp_in);
    fclose (fp_out);

    multiple_gcry_free (3, (gpointer *) &encryption_keys->derived_key,
                        (gpointer *) &encryption_keys->crypto_key,
                        (gpointer *) &encryption_keys->hmac_key);

    multiple_free (3, (gpointer *) &out_filename, (gpointer *) &encryption_keys, (gpointer *) &header_metadata);
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