#ifndef HASH_H
#define HASH_H

#define HASH_COMPUTED ((gpointer) 0)
#define HASH_ERROR ((gpointer) -2)
#define MUNMAP_FAILED ((gpointer) -3)
#define HMAC_ERROR ((gpointer) -4)

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

guchar *calculate_hmac (const gchar *file_path, const guchar *key, gsize keylen);

#endif
