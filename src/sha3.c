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
#include "gtkcrypto.h"

gpointer
compute_sha3 (gpointer user_data) {
	struct IdleData *func_data;
	struct hash_vars *hash_var = user_data;
	gint bit = 0;
	guint id = 0;
	gint entry_num;
	
	bit = hash_var->n_bit;
	
	if (bit == 256) {
		entry_num = 4;
		if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_var->hash_check[4]))) {
			func_data = g_slice_new (struct IdleData);
			func_data->entry = hash_var->hash_entry[entry_num];
			func_data->check = hash_var->hash_check[entry_num];
			g_idle_add (delete_entry_text, (gpointer)func_data);
			goto fine;
		}
		
		else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (hash_var->hash_entry[4])), -1) == 64)
			goto fine;
	
		gpointer ptr = g_hash_table_lookup (hash_var->hash_table, hash_var->key[4]);
		if (ptr != NULL) {
			func_data = g_slice_new (struct IdleData);
			func_data->entry = hash_var->hash_entry[entry_num];
			func_data->hash_table = hash_var->hash_table;
			func_data->key = hash_var->key[entry_num];
			func_data->check = hash_var->hash_check[entry_num];
			g_idle_add (stop_entry_progress, (gpointer)func_data);
			goto fine;
		}
		id = g_timeout_add (50, start_entry_progress, (gpointer)hash_var->hash_entry[entry_num]);
	}
	else if (bit == 384) {
		entry_num = 6;
		if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_var->hash_check[6]))) {
			func_data = g_slice_new (struct IdleData);
			func_data->entry = hash_var->hash_entry[entry_num];
			func_data->check = hash_var->hash_check[entry_num];
			g_idle_add (delete_entry_text, (gpointer)func_data);
			goto fine;
		}
		
		else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (hash_var->hash_entry[6])), -1) == 96)
			goto fine;	

		gpointer ptr = g_hash_table_lookup (hash_var->hash_table, hash_var->key[6]);
		if (ptr != NULL) {
			func_data = g_slice_new (struct IdleData);
			func_data->entry = hash_var->hash_entry[entry_num];
			func_data->hash_table = hash_var->hash_table;
			func_data->key = hash_var->key[entry_num];
			func_data->check = hash_var->hash_check[entry_num];
			g_idle_add (stop_entry_progress, (gpointer)func_data);
			goto fine;
		}
		id = g_timeout_add (50, start_entry_progress, (gpointer)hash_var->hash_entry[entry_num]);
	}
	else {
		entry_num = 8;
		if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_var->hash_check[8]))) {
			func_data = g_slice_new (struct IdleData);
			func_data->entry = hash_var->hash_entry[entry_num];
			func_data->check = hash_var->hash_check[entry_num];
			g_idle_add (delete_entry_text, (gpointer)func_data);
			goto fine;
		}
		
		else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (hash_var->hash_entry[8])), -1) == 128)
			goto fine;	

		gpointer ptr = g_hash_table_lookup (hash_var->hash_table, hash_var->key[8]);
		if (ptr != NULL) {
			func_data = g_slice_new (struct IdleData);
			func_data->entry = hash_var->hash_entry[entry_num];
			func_data->hash_table = hash_var->hash_table;
			func_data->key = hash_var->key[entry_num];
			func_data->check = hash_var->hash_check[entry_num];
			g_idle_add (stop_entry_progress, (gpointer)func_data);
			goto fine;
		}
		id = g_timeout_add (50, start_entry_progress, (gpointer)hash_var->hash_entry[entry_num]);
	}

	gint algo, i, fd, ret_val;
	gchar *hash;
	guint8 *addr;
	gsize file_size = 0, done_size = 0, diff = 0, offset = 0;
	GError *err = NULL;
    
    g_idle_add (stop_btn, (gpointer)hash_var);

	if (bit == 256) {
		const gchar *name = gcry_md_algo_name(GCRY_MD_SHA256);
		algo = gcry_md_map_name(name);
		hash = g_malloc (SHA256_DIGEST_SIZE * 2 + 1);
	}

	else if (bit == 384) {
		const gchar *name = gcry_md_algo_name(GCRY_MD_SHA384);
		algo = gcry_md_map_name(name);
		hash = g_malloc (SHA384_DIGEST_SIZE * 2 + 1);
	}

	else {
		const gchar *name = gcry_md_algo_name(GCRY_MD_SHA512);
		algo = gcry_md_map_name(name);
		hash = g_malloc (SHA512_DIGEST_SIZE * 2 + 1);
	}

	if (hash == NULL) {
		g_printerr ("sha3: error during memory allocation\n");
		g_thread_exit (NULL);
	}
	
	fd = g_open (hash_var->filename, O_RDONLY | O_NOFOLLOW);
	if (fd == -1) {
		g_printerr ("sha2: %s\n", g_strerror (errno));
		g_thread_exit (NULL);
	}
  	
  	file_size = (gsize) get_file_size (hash_var->filename);

	gcry_md_hd_t hd;
	gcry_md_open(&hd, algo, 0);
		
	if (file_size < BUF_FILE) {
		addr = mmap (NULL, file_size, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if (addr == MAP_FAILED) {
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (hash);
			g_close (fd, &err);
			g_thread_exit (NULL);
		}

		gcry_md_write (hd, addr, file_size);
		ret_val = munmap (addr, file_size);
		if (ret_val == -1) {
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (hash);
			g_close (fd, &err);
			g_thread_exit (NULL);
		}
		goto nowhile;
	}
	
	while (file_size > done_size) {
		addr = mmap (NULL, BUF_FILE, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
		if (addr == MAP_FAILED) {
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (hash);
			g_close (fd, &err);
			g_thread_exit (NULL);
		}

		gcry_md_write (hd, addr, BUF_FILE);
		done_size += BUF_FILE;
		diff = file_size - done_size;
		offset += BUF_FILE;
		
		if (diff < BUF_FILE && diff > 0) {
			addr = mmap (NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if (addr == MAP_FAILED) {
				g_printerr ("sha2: %s\n", g_strerror (errno));
				g_free (hash);
				g_close (fd, &err);
				g_thread_exit (NULL);
			}

            gcry_md_write (hd, addr, diff);
			ret_val = munmap(addr, diff);
			if(ret_val == -1) {
				g_printerr ("sha2: %s\n", g_strerror (errno));
				g_free (hash);
				g_close (fd, &err);
				g_thread_exit (NULL);
			}
			break;
		}
		
		ret_val = munmap (addr, BUF_FILE);
		if (ret_val == -1) {
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (hash);
			g_close (fd, &err);
			g_thread_exit (NULL);
		}
	}
	
	nowhile:
    gcry_md_final (hd);
	if (bit == 256) {
        guchar *sha3_256 = gcry_md_read (hd, algo);
		for (i = 0; i < SHA256_DIGEST_SIZE; i++)
			g_sprintf (hash+(i*2), "%02x", sha3_256[i]);

		hash[SHA256_DIGEST_SIZE * 2] = '\0';
		g_hash_table_insert (hash_var->hash_table, hash_var->key[4], strdup (hash));		
	}
	else if (bit == 384) {
        guchar *sha3_384 = gcry_md_read (hd, algo);
		for (i = 0; i < SHA384_DIGEST_SIZE; i++)
			g_sprintf (hash+(i*2), "%02x", sha3_384[i]);

		hash[SHA384_DIGEST_SIZE * 2] = '\0';
		g_hash_table_insert (hash_var->hash_table, hash_var->key[6], strdup (hash));		
	}
	else {
        guchar *sha3_512 = gcry_md_read (hd, algo);
		for (i = 0; i < SHA512_DIGEST_SIZE; i++)
			g_sprintf (hash+(i*2), "%02x", sha3_512[i]);

		hash[SHA512_DIGEST_SIZE * 2] = '\0';
		g_hash_table_insert (hash_var->hash_table, hash_var->key[8], strdup (hash));		
	}
 	
	g_close (fd, &err);
	g_free (hash);
	
	fine:
    g_idle_add (start_btn, (gpointer)hash_var);
	if (id > 0) {
		func_data = g_slice_new (struct IdleData);
		func_data->entry = hash_var->hash_entry[entry_num];
		func_data->hash_table = hash_var->hash_table;
		func_data->key = hash_var->key[entry_num];
		func_data->check = hash_var->hash_check[entry_num];
		g_idle_add (stop_entry_progress, (gpointer)func_data);
		g_source_remove (id);
	}
}
