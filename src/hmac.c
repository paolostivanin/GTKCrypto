#include <gtk/gtk.h>
#include <gcrypt.h>
#include <sys/mman.h>
#include "hash.h"


guchar *
calculate_hmac (const gchar *file_path, const guchar *key, gsize keylen)
{
    gcry_md_hd_t hd;
    gcry_md_open (&hd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey (hd, key, keylen);

    gpointer status = compute_hash (hd, file_path);
    if (status == MAP_FAILED) {
        g_printerr ("hmac: mmap error\n");
        return HMAC_ERROR;
    }
    else if (status == MUNMAP_FAILED) {
        g_printerr("hmac: munmap error\n");
        return HMAC_ERROR;
    }
    else if (status == HASH_ERROR) {
        return HMAC_ERROR;
    }

    gcry_md_final (hd);

    guchar *tmp_hmac = gcry_md_read (hd, GCRY_MD_SHA512);
    guchar *hmac = g_malloc (SHA512_DIGEST_SIZE);
    memcpy (hmac, tmp_hmac, SHA512_DIGEST_SIZE);

    gcry_md_close (hd);

    return hmac;
}
