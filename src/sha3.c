#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include <libnotify/notify.h>
#include <nettle/sha3.h>
#include <sys/mman.h>
#include "gtkcrypto.h"


gpointer
compute_sha3 (gpointer user_data)
{
	struct IdleData *func_data;
	struct hash_vars *hash_var = user_data;
	gint bit = 0;
	guint id = 0;
	gint entry_num;
	
	bit = hash_var->n_bit;
	
	if (bit == 256)
	{
		entry_num = 4;
		if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_var->hash_check[4])))
		{
			func_data = g_slice_new (struct IdleData);
			func_data->entry = hash_var->hash_entry[entry_num];
			func_data->check = hash_var->hash_check[entry_num];
			g_idle_add (delete_entry_text, (gpointer)func_data);
			goto fine;
		}
		
		else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (hash_var->hash_entry[4])), -1) == 64)
			goto fine;
	
		gpointer ptr = g_hash_table_lookup (hash_var->hash_table, hash_var->key[4]);
		if (ptr != NULL)
		{
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
	else if (bit == 384)
	{
		entry_num = 6;
		if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_var->hash_check[6])))
		{
			func_data = g_slice_new (struct IdleData);
			func_data->entry = hash_var->hash_entry[entry_num];
			func_data->check = hash_var->hash_check[entry_num];
			g_idle_add (delete_entry_text, (gpointer)func_data);
			goto fine;
		}
		
		else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (hash_var->hash_entry[6])), -1) == 96)
			goto fine;	

		gpointer ptr = g_hash_table_lookup (hash_var->hash_table, hash_var->key[6]);
		if (ptr != NULL)
		{
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
	else
	{
		entry_num = 8;
		if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_var->hash_check[8])))
		{
			func_data = g_slice_new (struct IdleData);
			func_data->entry = hash_var->hash_entry[entry_num];
			func_data->check = hash_var->hash_check[entry_num];
			g_idle_add (delete_entry_text, (gpointer)func_data);
			goto fine;
		}
		
		else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (hash_var->hash_entry[8])), -1) == 128)
			goto fine;	

		gpointer ptr = g_hash_table_lookup (hash_var->hash_table, hash_var->key[8]);
		if (ptr != NULL)
		{
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
	
	guchar *digest;
	gchar *hash;
	GError *err = NULL;
	gint fd, i, ret_val;
	goffset file_size, done_size = 0, diff = 0, offset = 0;
	guint8 *addr;
	
	struct sha3_256_ctx ctx256;
	struct sha3_384_ctx ctx384;
	struct sha3_512_ctx ctx512;
	
	if (bit == 256)
	{
		digest = g_malloc (SHA3_256_DIGEST_SIZE);
		hash = g_malloc ((SHA3_256_DIGEST_SIZE * 2) + 1);
	}
		
	else if (bit == 384)
	{
		digest = g_malloc (SHA3_384_DIGEST_SIZE);
		hash = g_malloc ((SHA3_384_DIGEST_SIZE * 2) + 1);
	}
	
	else
	{
		digest = g_malloc (SHA3_512_DIGEST_SIZE);
		hash = g_malloc ((SHA3_512_DIGEST_SIZE * 2) + 1);
	}
	
	if (digest == NULL)
	{
		g_printerr ("sha2: error during memory allocation\n");
		g_thread_exit (NULL);
	}
	
	if (hash == NULL)
	{
		g_printerr ("sha2: error during memory allocation\n");
		g_free (digest);
		g_thread_exit (NULL);
	}
	
	fd = g_open (hash_var->filename, O_RDONLY | O_NOFOLLOW);
	if (fd == -1)
	{
		g_printerr ("sha2: %s\n", g_strerror (errno));
		g_thread_exit (NULL);
	}
  	
  	file_size = get_file_size (hash_var->filename);
  	
  	if (bit == 256)
		sha3_256_init (&ctx256);
	
	else if (bit == 384)
		sha3_384_init (&ctx384);
	
	else
		sha3_512_init (&ctx512);
		
	if (file_size < BUF_FILE)
	{
		addr = mmap (NULL, file_size, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if (addr == MAP_FAILED)
		{
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (digest);
			g_free (hash);
			g_close (fd, &err);
			g_thread_exit (NULL);
		}
		if (bit == 256)
			sha3_256_update (&ctx256, file_size, addr);
		
		else if (bit == 384)
			sha3_384_update (&ctx384, file_size, addr);
		
		else
			sha3_512_update (&ctx512, file_size, addr);
			
		ret_val = munmap (addr, file_size);
		if (ret_val == -1)
		{
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (digest);
			g_free (hash);
			g_close (fd, &err);
			g_thread_exit (NULL);
		}
		goto nowhile;
	}
	
	while (file_size > done_size)
	{
		addr = mmap (NULL, BUF_FILE, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
		if (addr == MAP_FAILED)
		{
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (digest);
			g_free (hash);
			g_close (fd, &err);
			g_thread_exit (NULL);
		}
		
		if (bit == 256)
			sha3_256_update (&ctx256, BUF_FILE, addr);
		
		else if (bit == 384)
			sha3_384_update (&ctx384, BUF_FILE, addr);
		
		else
			sha3_512_update (&ctx512, BUF_FILE, addr);
		
		done_size += BUF_FILE;
		diff = file_size - done_size;
		offset += BUF_FILE;
		
		if (diff < BUF_FILE && diff > 0)
		{
			addr = mmap (NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if (addr == MAP_FAILED)
			{
				g_printerr ("sha2: %s\n", g_strerror (errno));
				g_free (digest);
				g_free (hash);
				g_close (fd, &err);
				g_thread_exit (NULL);
			}
			
			if (bit == 256)
				sha3_256_update (&ctx256, diff, addr);
			
			else if (bit == 384)
				sha3_384_update (&ctx384, diff, addr);
			
			else
				sha3_512_update (&ctx512, diff, addr);
				
			ret_val = munmap(addr, diff);
			if(ret_val == -1){
				g_printerr ("sha2: %s\n", g_strerror (errno));
				g_free (digest);
				g_free (hash);
				g_close (fd, &err);
				g_thread_exit (NULL);
			}
			break;
		}
		
		ret_val = munmap(addr, BUF_FILE);
		if(ret_val == -1)
		{
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (digest);
			g_free (hash);
			g_close (fd, &err);
			g_thread_exit (NULL);
		}
	}
	
	nowhile:
	if (bit == 256)
	{
		sha3_256_digest(&ctx256, SHA3_256_DIGEST_SIZE, digest);
		for (i = 0; i < SHA3_256_DIGEST_SIZE; i++)
			g_sprintf (hash+(i*2), "%02x", digest[i]);

		hash[SHA3_256_DIGEST_SIZE * 2] = '\0';
		g_hash_table_insert (hash_var->hash_table, hash_var->key[4], strdup (hash));		
	}
	else if (bit == 384)
	{
		sha3_384_digest(&ctx384, SHA3_384_DIGEST_SIZE, digest);
		for (i = 0; i < SHA3_384_DIGEST_SIZE; i++)
			g_sprintf (hash+(i*2), "%02x", digest[i]);

		hash[SHA3_384_DIGEST_SIZE * 2] = '\0';
		g_hash_table_insert (hash_var->hash_table, hash_var->key[6], strdup (hash));		
	}
	else
	{
		sha3_512_digest(&ctx512, SHA3_512_DIGEST_SIZE, digest);
		for (i = 0; i < SHA3_512_DIGEST_SIZE; i++)
			g_sprintf (hash+(i*2), "%02x", digest[i]);

		hash[SHA3_512_DIGEST_SIZE * 2] = '\0';
		g_hash_table_insert (hash_var->hash_table, hash_var->key[8], strdup (hash));		
	}
 	
	g_close (fd, &err);
	g_free (digest);
	g_free (hash);
	
	fine:
	if (id > 0)
	{
		func_data = g_slice_new (struct IdleData);
		func_data->entry = hash_var->hash_entry[entry_num];
		func_data->hash_table = hash_var->hash_table;
		func_data->key = hash_var->key[entry_num];
		func_data->check = hash_var->hash_check[entry_num];
		g_idle_add (stop_entry_progress, (gpointer)func_data);
		g_source_remove (id);
	}
}
