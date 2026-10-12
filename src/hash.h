#pragma once

#include <glib.h>
#include <gio/gio.h>
#include <gcrypt.h>

#define HASH_COMPUTED         ((gpointer) 10)
#define HASH_ERROR            ((gpointer) 11)
#define MUNMAP_FAILED         ((gpointer) 12)

#define AVAILABLE_HASH_TYPE   12

#define MD5_DIGEST_SIZE         16
#define SHA1_DIGEST_SIZE        20
#define GOST94_DIGEST_SIZE      32
#define SHA256_DIGEST_SIZE      32
#define SHA3_256_DIGEST_SIZE    32
#define BLAKE2B_256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE      48
#define SHA3_384_DIGEST_SIZE    48
#define SHA512_DIGEST_SIZE      64
#define SHA3_512_DIGEST_SIZE    64
#define BLAKE2B_512_DIGEST_SIZE 64
#define WHIRLPOOL_DIGEST_SIZE   64


gpointer compute_hash   (gcry_md_hd_t *hd,
                         const gchar  *file_path);

gchar *finalize_hash    (gcry_md_hd_t *hd,
                         gint          algo,
                         gint          digest_size);

/* Hash FILE_PATH with all ALGOS in a single read pass. On success hex_out[i]
 * holds the lowercase hex digest for algos[i] (free each with g_free). */
gboolean gtkcrypto_hash_file (const gchar  *file_path,
                              const gint   *algos,
                              const gint   *digest_sizes,
                              guint         n_algos,
                              GCancellable *cancellable,
                              gchar       **hex_out,
                              GError      **error);

/* Same as gtkcrypto_hash_file() for an already open descriptor (e.g. a pipe).
 * NAME is only used in error messages. The descriptor is not closed. */
gboolean gtkcrypto_hash_fd   (gint          fd,
                              const gchar  *name,
                              const gint   *algos,
                              const gint   *digest_sizes,
                              guint         n_algos,
                              GCancellable *cancellable,
                              gchar       **hex_out,
                              GError      **error);
