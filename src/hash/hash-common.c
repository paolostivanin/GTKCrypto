#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <sys/mman.h>
#include <errno.h>
#include "hash.h"
#include "../gtkcrypto.h"


gchar *finalize_hash (gcry_md_hd_t hd, gint algo, gsize DIGEST_SIZE) {
    gcry_md_final (hd);
    gchar *finalized_hash = g_malloc(DIGEST_SIZE * 2 + 1);
    guchar *hash = gcry_md_read (hd, algo);
    gint i;

    for (i = 0; i < DIGEST_SIZE; i++)
        g_sprintf (finalized_hash+(i*2), "%02x", hash[i]);

    finalized_hash[DIGEST_SIZE * 2] = '\0';

    gcry_md_close (hd);

    return finalized_hash;
}


void add_idle_and_check_id (guint id, struct hash_vars *hash_var, gint pos) {
    struct IdleData *func_data;
    g_idle_add (start_btn, (gpointer)hash_var);
    if (id > 0) {
        func_data = g_slice_new (struct IdleData);
        func_data->entry = hash_var->hash_entry[pos];
        func_data->hash_table = hash_var->hash_table;
        func_data->key = hash_var->key[pos];
        func_data->check = hash_var->hash_check[pos];
        g_idle_add (stop_entry_progress, (gpointer)func_data);
        g_source_remove (id);
    }
}


gpointer compute_hash (gcry_md_hd_t hd, gsize file_size, int fd) {
    guint8 *addr;
    gint ret_val;
    gsize done_size = 0, diff = 0, offset = 0;

    if (file_size < BUF_FILE) {
        addr = mmap (NULL, file_size, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
        if (addr == MAP_FAILED) {
            return MAP_FAILED;
        }
        gcry_md_write (hd, addr, file_size);
        ret_val = munmap (addr, file_size);
        if (ret_val == -1) {
            return MUNMAP_FAILED;
        }
        return HASH_COMPUTED;
    }
    else {
        while (file_size > done_size) {
            addr = mmap(NULL, BUF_FILE, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
            if (addr == MAP_FAILED) {
                return MAP_FAILED;
            }
            gcry_md_write(hd, addr, BUF_FILE);
            done_size += BUF_FILE;
            diff = file_size - done_size;
            offset += BUF_FILE;
            if (diff < BUF_FILE && diff > 0) {
                addr = mmap(NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
                if (addr == MAP_FAILED) {
                    return MAP_FAILED;
                }
                gcry_md_write(hd, addr, diff);
                ret_val = munmap(addr, diff);
                if (ret_val == -1) {
                    return MUNMAP_FAILED;
                }
                break;
            }
            ret_val = munmap(addr, BUF_FILE);
            if (ret_val == -1) {
                return MUNMAP_FAILED;
            }
        }
        return HASH_COMPUTED;
    }
}