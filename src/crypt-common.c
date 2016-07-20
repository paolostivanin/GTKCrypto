#include <gtk/gtk.h>
#include <gcrypt.h>
#include "crypt-common.h"


gboolean
setup_keys (const gchar *pwd, gsize algo_key_len, Metadata *header_metadata, CryptoKeys *keys)
{
    keys->derived_key = gcry_malloc_secure (algo_key_len + HMAC_KEY_SIZE);
    if (keys->derived_key == NULL) {
        return FALSE;
    }

    if (gcry_kdf_derive (pwd, (gsize) g_utf8_strlen (pwd, -1) + 1, GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                         header_metadata->salt, KDF_SALT_SIZE, KDF_ITERATIONS, algo_key_len + HMAC_KEY_SIZE, keys->derived_key) != 0) {
        return FALSE;
    }

    keys->crypto_key = gcry_malloc_secure (algo_key_len);
    if (keys->crypto_key == NULL) {
        return FALSE;
    }
    memcpy (keys->crypto_key, keys->derived_key, algo_key_len);

    keys->hmac_key = gcry_malloc_secure (HMAC_KEY_SIZE);
    if (keys->hmac_key == NULL) {
        return FALSE;
    }
    memcpy (keys->hmac_key, keys->derived_key + algo_key_len, HMAC_KEY_SIZE);

    return TRUE;
}
