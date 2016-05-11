#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gi18n.h>
#include <sys/mman.h>
#include "hash.h"
#include "../gtkcrypto.h"

//mode = 0 encrypt, mode = 1 decrypt

guchar *calculate_hmac(const gchar *filename, const guchar *key, gsize keylen, goffset fsize) {
    gint fd;
    gsize file_size;
    GError *err = NULL;

    file_size = (gsize) fsize;

    fd = g_open(filename, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) {
        g_printerr("calculate_hmac: %s\n", g_strerror(errno));
        return (guchar *) 1;
    }

    gcry_md_hd_t hd;
    gcry_md_open(&hd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(hd, key, keylen);

    gpointer status = compute_hash(hd, file_size, fd);
    if (status == MAP_FAILED) {
        g_printerr("hmac: mmap error\n");
        return (guchar *) 1;
    }
    else if (status == MUNMAP_FAILED) {
        g_printerr("hmac: munmap error\n");
        return (guchar *) 1;
    }

    g_close(fd, &err);
    gcry_md_final (hd);
    guchar *tmp_hmac = gcry_md_read(hd, GCRY_MD_SHA512);
    guchar *hmac = g_malloc(SHA512_DIGEST_SIZE);
    memcpy(hmac, tmp_hmac, SHA512_DIGEST_SIZE);
    gcry_md_close(hd);

    return hmac;
}
