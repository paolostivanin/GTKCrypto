#include <gtk/gtk.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <sys/mman.h>
#include <errno.h>
#include "hash.h"
#include "gtkcrypto.h"


gchar *
get_file_hash (const gchar *filename, gint hash_algo, gint digest_size)
{
    const gchar *name = gcry_md_algo_name (hash_algo);
    gint algo = gcry_md_map_name (name);

    gcry_md_hd_t hd;
    gcry_md_open(&hd, algo, 0);

    gpointer status = compute_hash (hd, filename);
    if (status == MAP_FAILED) {
        g_printerr ("mmap error\n");
        return NULL;
    }
    else if (status == MUNMAP_FAILED) {
        g_printerr ("munmap error\n");
        return NULL;
    }
    else if (status == HASH_ERROR) {
        return NULL;
    }
    else {
        return finalize_hash (hd, algo, digest_size);
    }
}


gpointer
compute_hash (gcry_md_hd_t hd, const gchar *filename)
{
    guint8 *addr;
    gint ret_val = 0;
    gsize done_size = 0, diff = 0, offset = 0;

    goffset file_size = get_file_size (filename);
    if (file_size == -1) {
        g_printerr ("Error while getting file size\n");
        return HASH_ERROR;
    }

    gint fd = g_open (filename, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) {
        g_printerr ("%s\n", g_strerror (errno));
        return HASH_ERROR;
    }
    if (file_size < FILE_BUFFER) {
        addr = mmap (NULL, (gsize) file_size, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
        if (addr == MAP_FAILED) {
            g_close (fd, NULL);
            return MAP_FAILED;
        }
        gcry_md_write (hd, addr, (gsize) file_size);
        ret_val = munmap (addr, (gsize) file_size);
        if (ret_val == -1) {
            g_close (fd, NULL);
            return MUNMAP_FAILED;
        }
        g_close (fd, NULL);
        return HASH_COMPUTED;
    }
    else {
        while (file_size > done_size) {
            addr = mmap (NULL, FILE_BUFFER, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
            if (addr == MAP_FAILED) {
                g_close (fd, NULL);
                return MAP_FAILED;
            }
            gcry_md_write (hd, addr, FILE_BUFFER);
            done_size += FILE_BUFFER;
            diff = file_size - done_size;
            offset += FILE_BUFFER;
            if (diff < FILE_BUFFER && diff > 0) {
                addr = mmap (NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
                if (addr == MAP_FAILED) {
                    g_close (fd, NULL);
                    return MAP_FAILED;
                }
                gcry_md_write (hd, addr, diff);
                ret_val = munmap (addr, diff);
                if (ret_val == -1) {
                    g_close (fd, NULL);
                    return MUNMAP_FAILED;
                }
                break;
            }
            ret_val = munmap (addr, FILE_BUFFER);
            if (ret_val == -1) {
                g_close (fd, NULL);
                return MUNMAP_FAILED;
            }
        }
        g_close (fd, NULL);
        return HASH_COMPUTED;
    }
}


gchar *
finalize_hash (gcry_md_hd_t hd, gint algo, gint digest_size)
{
    gcry_md_final (hd);
    gchar *finalized_hash = g_malloc ((gsize) digest_size * 2 + 1);
    guchar *hash = gcry_md_read (hd, algo);
    gint i;

    for (i = 0; i < digest_size; i++)
        g_sprintf (finalized_hash + (i*2), "%02x", hash[i]);

    finalized_hash[digest_size * 2] = '\0';

    gcry_md_close (hd);

    return finalized_hash;
}
