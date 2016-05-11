//
// Created by polslinux on 10/05/16.
//

#ifndef GTKCRYPTO_HASH_H
#define GTKCRYPTO_HASH_H

#include <gcrypt.h>
#include "../gtkcrypto.h"

#define BUF_FILE 16777216 /* 16 MiB memory buffer (hash) */

#define MD5_DIGEST_SIZE 16
#define SHA1_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32
#define GOST94_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64
#define WHIRLPOOL_DIGEST_SIZE 64

#define MUNMAP_FAILED	((void *) -2)
#define HASH_COMPUTED	((void *) 1)

gchar *finalize_hash (gcry_md_hd_t, gint, gsize);
void add_idle_and_check_id (guint, struct hash_vars *hash_var, gint);
gpointer compute_hash (gcry_md_hd_t, gsize, int);

#endif //GTKCRYPTO_HASH_H
