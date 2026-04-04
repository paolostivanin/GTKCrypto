#pragma once

#include <glib.h>
#include <gcrypt.h>

// The encryption/decryption key is derived using PBKDF2 with SHA512 while the HMAC function uses `SHA_3_512`.

#define MAX_IV_SIZE             16
#define GCM_IV_SIZE             12
#define HMAC_KEY_SIZE           64
#define KDF_ITERATIONS          600000
#define KDF_ITERATIONS_LEGACY   100000
#define KDF_SALT_SIZE           32

#define AES256_KEY_SIZE         32
#define AES256_BLOCK_SIZE       16
#define AES256_IV_SIZE          AES256_BLOCK_SIZE
#define TAG_SIZE                AES256_BLOCK_SIZE

#define METADATA_MAGIC_0        'G'
#define METADATA_MAGIC_1        'T'
#define METADATA_MAGIC_2        'C'
#define METADATA_VERSION        2

typedef struct header_metadata_t {
    guint8 magic[3];
    guint8 version;
    guint8 iv[MAX_IV_SIZE];
    guint8 iv_size;
    guint8 salt[KDF_SALT_SIZE];
    gint algo;
    gint algo_mode;
    guint8 padding_value;
} __attribute__((packed)) Metadata;

typedef struct key_t {
    guchar *derived_key;
    guchar *crypto_key;
    guchar *hmac_key;
} CryptoKeys;

gboolean setup_keys (const gchar *pwd, gsize algo_key_len, guint iterations, Metadata *header_metadata, CryptoKeys *encryption_keys);
