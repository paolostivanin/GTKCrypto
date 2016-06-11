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

static void set_algo_and_mode (Metadata *, const gchar *, const gchar *);


void
encrypt_file (const gchar *filename, const gchar *pwd, const gchar *algo, const gchar *algo_mode)
{
    Metadata *header_metadata = g_new0 (Metadata, 1);

    set_algo_and_mode (header_metadata, algo, algo_mode);
    gsize key_len = gcry_cipher_get_algo_keylen (header_metadata->algo);

    guchar *derived_key = gcry_malloc_secure (64);
    if (derived_key == NULL) {
        // TODO
        return;
    }

    gcry_create_nonce (header_metadata->salt, SALT_SIZE);

    if (gcry_kdf_derive (pwd, strlen (pwd) + 1, GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                         header_metadata->salt, SALT_SIZE, ROUNDS, 64, derived_key) != 0) {
        // TODO
        return;
    }

    guchar *crypto_key = gcry_malloc_secure (key_len);
    if (crypto_key == NULL) {
        //TODO
        return;
    }
    memcpy (crypto_key, derived_key, key_len);

    guchar *hmac_key = gcry_malloc_secure (HMAC_KEY_SIZE);
    if (hmac_key == NULL) {
        //TODO
        return;
    }
    memcpy (hmac_key, derived_key + key_len, HMAC_KEY_SIZE);

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

    /* if CBC number of blocks...
     * if CTR no problems
     */

    gcry_free (derived_key);
    gcry_free (crypto_key);
    gcry_free (hmac_key);

    g_free (out_filename);
    g_free (header_metadata);
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