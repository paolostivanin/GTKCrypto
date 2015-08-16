#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include <nettle/gosthash94.h>
#include <sys/mman.h>
#include "gtkcrypto.h"


gpointer
compute_gost94 (gpointer user_data)
{
	struct IdleData *func_data;
	struct hash_vars *hash_var = user_data;
	guint id = 0;
	
   	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_var->hash_check[1])))
   	{
		func_data = g_slice_new (struct IdleData);
		func_data->entry = hash_var->hash_entry[1];
		func_data->check = hash_var->hash_check[1];
		g_idle_add (delete_entry_text, (gpointer)func_data);
		goto fine;
	}
	
	else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (hash_var->hash_entry[1])), -1) == 32)
		goto fine;
		
	gpointer ptr = g_hash_table_lookup (hash_var->hash_table, hash_var->key[1]);
	if (ptr != NULL)
	{
		func_data = g_slice_new (struct IdleData);
		func_data->entry = hash_var->hash_entry[1];
		func_data->hash_table = hash_var->hash_table;
		func_data->key = hash_var->key[1];
		func_data->check = hash_var->hash_check[1];
		g_idle_add (stop_entry_progress, (gpointer)func_data);
		goto fine;
	}
	
	id = g_timeout_add (50, start_entry_progress, (gpointer)hash_var->hash_entry[1]);
	g_idle_add (stop_btn, (gpointer)hash_var);
    
	struct gosthash94_ctx ctx;
	guint8 digest[GOSTHASH94_DIGEST_SIZE];
	gint fd, i, ret_val;
	goffset file_size, done_size = 0, diff = 0, offset = 0;
	gchar hash[(GOSTHASH94_DIGEST_SIZE * 2) + 1];
	guint8 *addr;
	GError *err = NULL;
	
	fd = g_open (hash_var->filename, O_RDONLY | O_NOFOLLOW);
	if (fd == -1)
	{
		g_printerr ("gost94: %s\n", g_strerror (errno));
		g_thread_exit (NULL);
	}
	
  	file_size = get_file_size (hash_var->filename);
       
	gosthash94_init (&ctx);

	if (file_size < BUF_FILE)
	{
		addr = mmap (NULL, file_size, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if (addr == MAP_FAILED)
		{
			g_printerr ("gost94: %s\n", g_strerror (errno));
			g_thread_exit (NULL);
		}
		gosthash94_update (&ctx, file_size, addr);
		ret_val = munmap (addr, file_size);
		if(ret_val == -1)
		{
			g_printerr ("gost94: munmap error\n");
			g_thread_exit (NULL);
		}
		goto nowhile;
	}

	while (file_size > done_size)
	{
		addr = mmap (NULL, BUF_FILE, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
		if (addr == MAP_FAILED)
		{
			g_printerr ("gost94: %s\n", g_strerror (errno));
			g_thread_exit (NULL);
		}
		gosthash94_update (&ctx, BUF_FILE, addr);
		done_size += BUF_FILE;
		diff = file_size - done_size;
		offset += BUF_FILE;
		if (diff < BUF_FILE && diff > 0)
		{
			addr = mmap (NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if (addr == MAP_FAILED)
			{
				g_printerr ("gost94: %s\n", g_strerror (errno));
				g_thread_exit (NULL);
			}
			gosthash94_update (&ctx, diff, addr);
			ret_val = munmap (addr, diff);
			if (ret_val == -1)
			{
				g_printerr ("gost94: munmap error\n");
				g_thread_exit (NULL);
			}
			break;
		}
		ret_val = munmap (addr, BUF_FILE);
		if (ret_val == -1)
		{
			g_printerr ("gost94: munmap error\n");
			g_thread_exit (NULL);
		}
	}
	
	nowhile:	
	gosthash94_digest (&ctx, GOSTHASH94_DIGEST_SIZE, digest);
 	for (i = 0; i < GOSTHASH94_DIGEST_SIZE; i++)
		g_sprintf (hash+(i*2), "%02x", digest[i]);

 	hash[GOSTHASH94_DIGEST_SIZE * 2] = '\0';
 	g_hash_table_insert (hash_var->hash_table, hash_var->key[1], g_strdup (hash));
 	
	g_close(fd, &err);
	
	fine:
    g_idle_add (start_btn, (gpointer)hash_var);
	if (id > 0)
	{
		func_data = g_slice_new (struct IdleData);
		func_data->entry = hash_var->hash_entry[1];
		func_data->hash_table = hash_var->hash_table;
		func_data->key = hash_var->key[1];
		func_data->check = hash_var->hash_check[1];
		g_idle_add (stop_entry_progress, (gpointer)func_data);
		g_source_remove (id);
	}
}
