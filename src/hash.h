#ifndef HASH_H
#define HASH_H

#define MUNMAP_FAILED ((gpointer) -2)
#define HASH_ERROR ((gpointer) -3)
#define HASH_COMPUTED ((gpointer) 0)

#define FILE_BUFFER 134217728  //128 MiB

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

gpointer compute_hash (gcry_md_hd_t, const gchar *);

gchar *finalize_hash (gcry_md_hd_t, gint, gint);

#endif
