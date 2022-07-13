#pragma once

// The encryption/decryption key is derived using PBKDF2 with SHA512 while the HMAC function uses `SHA_3_512`.

#define MAX_IV_SIZE         16
#define HMAC_KEY_SIZE       64
#define KDF_ITERATIONS      100000
#define KDF_SALT_SIZE       32

#define AES256_KEY_SIZE     32
#define AES256_BLOCK_SIZE   16
#define AES256_IV_SIZE      AES256_BLOCK_SIZE
#define TAG_SIZE            AES256_BLOCK_SIZE

typedef struct header_metadata_t {
    guint8 iv[MAX_IV_SIZE];
    gsize iv_size;
    guint8 salt[KDF_SALT_SIZE];
    gint algo;
    gint algo_mode;
    guint8 padding_value;
} Metadata;

typedef struct key_t {
    guchar *derived_key;
    guchar *crypto_key;
    guchar *hmac_key;
} CryptoKeys;

gboolean setup_keys (const gchar *pwd, gsize algo_key_len, Metadata *header_metadata, CryptoKeys *encryption_keys);
