#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include <sys/mman.h>
#include "hash.h"
#include "../gtkcrypto.h"


gpointer compute_sha2(gpointer user_data) {
    struct IdleData *func_data;
    struct hash_vars *hash_var = user_data;
    gint bit = 0;
    guint id = 0;
    gint entry_num;

    bit = hash_var->n_bit;

    if (bit == 256) {
        entry_num = 3;
        if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (hash_var->hash_check[entry_num]))) {
            func_data = g_slice_new (struct IdleData);
            func_data->entry = hash_var->hash_entry[entry_num];
            func_data->check = hash_var->hash_check[entry_num];
            g_idle_add(delete_entry_text, (gpointer) func_data);
            goto fine;
        }

        else if (g_utf8_strlen(gtk_entry_get_text(GTK_ENTRY (hash_var->hash_entry[entry_num])), -1) == 64)
            goto fine;

        gpointer ptr = g_hash_table_lookup(hash_var->hash_table, hash_var->key[entry_num]);
        if (ptr != NULL) {
            func_data = g_slice_new (struct IdleData);
            func_data->entry = hash_var->hash_entry[entry_num];
            func_data->hash_table = hash_var->hash_table;
            func_data->key = hash_var->key[entry_num];
            func_data->check = hash_var->hash_check[entry_num];
            g_idle_add(stop_entry_progress, (gpointer) func_data);
            goto fine;
        }
        id = g_timeout_add(50, start_entry_progress, (gpointer) hash_var->hash_entry[entry_num]);
    }
    else if (bit == 384) {
        entry_num = 5;
        if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (hash_var->hash_check[entry_num]))) {
            func_data = g_slice_new (struct IdleData);
            func_data->entry = hash_var->hash_entry[entry_num];
            func_data->check = hash_var->hash_check[entry_num];
            g_idle_add(delete_entry_text, (gpointer) func_data);
            goto fine;
        }

        else if (g_utf8_strlen(gtk_entry_get_text(GTK_ENTRY (hash_var->hash_entry[entry_num])), -1) == 96)
            goto fine;

        gpointer ptr = g_hash_table_lookup(hash_var->hash_table, hash_var->key[entry_num]);
        if (ptr != NULL) {
            func_data = g_slice_new (struct IdleData);
            func_data->entry = hash_var->hash_entry[entry_num];
            func_data->hash_table = hash_var->hash_table;
            func_data->key = hash_var->key[entry_num];
            func_data->check = hash_var->hash_check[entry_num];
            g_idle_add(stop_entry_progress, (gpointer) func_data);
            goto fine;
        }
        id = g_timeout_add(50, start_entry_progress, (gpointer) hash_var->hash_entry[entry_num]);
    }
    else {
        entry_num = 7;
        if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (hash_var->hash_check[entry_num]))) {
            func_data = g_slice_new (struct IdleData);
            func_data->entry = hash_var->hash_entry[entry_num];
            func_data->check = hash_var->hash_check[entry_num];
            g_idle_add(delete_entry_text, (gpointer) func_data);
            goto fine;
        }

        else if (g_utf8_strlen(gtk_entry_get_text(GTK_ENTRY (hash_var->hash_entry[entry_num])), -1) == 128)
            goto fine;

        gpointer ptr = g_hash_table_lookup(hash_var->hash_table, hash_var->key[entry_num]);
        if (ptr != NULL) {
            func_data = g_slice_new (struct IdleData);
            func_data->entry = hash_var->hash_entry[entry_num];
            func_data->hash_table = hash_var->hash_table;
            func_data->key = hash_var->key[entry_num];
            func_data->check = hash_var->hash_check[entry_num];
            g_idle_add(stop_entry_progress, (gpointer) func_data);
            goto fine;
        }
        id = g_timeout_add(50, start_entry_progress, (gpointer) hash_var->hash_entry[entry_num]);
    }

    gint algo, fd;
    gsize file_size = 0;
    GError *err = NULL;

    g_idle_add(stop_btn, (gpointer) hash_var);

    if (bit == 256) {
        const gchar *name = gcry_md_algo_name(GCRY_MD_SHA256);
        algo = gcry_md_map_name(name);
    }
    else if (bit == 384) {
        const gchar *name = gcry_md_algo_name(GCRY_MD_SHA384);
        algo = gcry_md_map_name(name);
    }
    else {
        const gchar *name = gcry_md_algo_name(GCRY_MD_SHA512);
        algo = gcry_md_map_name(name);
    }

    fd = g_open(hash_var->filename, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) {
        g_printerr("sha2: %s\n", g_strerror(errno));
        g_thread_exit(NULL);
    }

    file_size = (gsize) get_file_size(hash_var->filename);

    gcry_md_hd_t hd;
    gcry_md_open(&hd, algo, 0);

    gpointer status = compute_hash(hd, file_size, fd);
    if (status == MAP_FAILED) {
        g_printerr("sha2: mmap error\n");
        g_thread_exit(NULL);
    }
    else if (status == MUNMAP_FAILED) {
        g_printerr("sha2: munmap error\n");
        g_thread_exit(NULL);
    }

    g_close(fd, &err);
    if (bit == 256) {
        gchar *hash = finalize_hash(hd, algo, SHA256_DIGEST_SIZE);
        g_hash_table_insert(hash_var->hash_table, hash_var->key[3], g_strdup(hash));
        g_free(hash);
    }
    else if (bit == 384) {
        gchar *hash = finalize_hash(hd, algo, SHA384_DIGEST_SIZE);
        g_hash_table_insert(hash_var->hash_table, hash_var->key[5], g_strdup(hash));
        g_free(hash);
    }
    else {
        gchar *hash = finalize_hash(hd, algo, SHA512_DIGEST_SIZE);
        g_hash_table_insert(hash_var->hash_table, hash_var->key[7], g_strdup(hash));
        g_free(hash);
    }

    fine:
    add_idle_and_check_id(id, hash_var, entry_num);
}
