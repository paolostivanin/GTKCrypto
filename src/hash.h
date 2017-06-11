#pragma once

#define HASH_COMPUTED ((gpointer) 10)
#define HASH_ERROR ((gpointer) 11)
#define MUNMAP_FAILED ((gpointer) 12)
#define HMAC_OK ((gpointer) 13)
#define HMAC_MISMATCH ((gpointer) 14)

#define FILE_BUFFER 67108864 // 64 MiB

#define AVAILABLE_HASH_TYPE 10

#define MD5_DIGEST_SIZE 16
#define SHA1_DIGEST_SIZE 20
#define GOST94_DIGEST_SIZE 32
#define SHA256_DIGEST_SIZE 32
#define SHA3_256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA3_384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64
#define SHA3_512_DIGEST_SIZE 64
#define WHIRLPOOL_DIGEST_SIZE 64

gpointer compute_hash (gcry_md_hd_t *hd, const gchar *file_path);

gchar *finalize_hash (gcry_md_hd_t *hd, gint algo, gint digest_size);

guchar *calculate_hmac (const gchar *file_path, const guchar *key, guchar *user_hmac);
