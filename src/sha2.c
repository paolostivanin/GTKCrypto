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
#include <nettle/sha2.h>
#include <sys/mman.h>
#include "polcrypt.h"


void
compute_sha2 (	GtkWidget *checkBt,
		struct hash_vars *hash_var)
{
	gint bit = 0;
	
	if (g_strcmp0 (gtk_widget_get_name (checkBt), "BtSha256") == 0)
		bit = 256;
	else if (g_strcmp0 (gtk_widget_get_name (checkBt), "BtSha384") == 0)
		bit = 384;
	else if (g_strcmp0 (gtk_widget_get_name (checkBt), "BtSha512") == 0)
		bit = 512;
	
	if (bit == 256)
	{
		if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_var->hash_check[3])))
		{
			gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[3]), "");
			goto fine;
		}
		
		else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (hash_var->hash_entry[3])), -1) == 64)
			goto fine;
			
		gpointer ptr = g_hash_table_lookup (hash_var->hash_table, hash_var->key[3]);
		if (ptr != NULL)
		{
			gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[3]), (gchar *)g_hash_table_lookup (hash_var->hash_table, hash_var->key[3]));
			goto fine;
		}
	}
	else if (bit == 384)
	{
		if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_var->hash_check[5])))
		{
			gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[5]), "");
			goto fine;
		}
		
		else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (hash_var->hash_entry[5])), -1) == 96)
			goto fine;
		
		gpointer ptr = g_hash_table_lookup (hash_var->hash_table, hash_var->key[5]);
		if (ptr != NULL)
		{
			gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[5]), (gchar *)g_hash_table_lookup (hash_var->hash_table, hash_var->key[5]));
			goto fine;
		}		
	}
	else
	{
		if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_var->hash_check[7])))
		{
			gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[7]), "");
			goto fine;
		}
		
		else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (hash_var->hash_entry[7])), -1) == 128)
			goto fine;
		
		gpointer ptr = g_hash_table_lookup (hash_var->hash_table, hash_var->key[7]);
		if (ptr != NULL)
		{
			gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[7]), (gchar *)g_hash_table_lookup (hash_var->hash_table, hash_var->key[7]));
			goto fine;
		}		
	}
	
	guchar *digest;
	gchar *hash;
	GError *err = NULL;
	gint fd, i, retVal;
	goffset fileSize, doneSize = 0, diff = 0, offset = 0;
	guint8 *fAddr;
	
	struct sha256_ctx ctx256;
	struct sha384_ctx ctx384;
	struct sha512_ctx ctx512;
	
	if (bit == 256)
	{
		digest = g_malloc (SHA256_DIGEST_SIZE);
		hash = g_malloc ((SHA256_DIGEST_SIZE * 2) + 1);
	}
		
	else if (bit == 384)
	{
		digest = g_malloc (SHA384_DIGEST_SIZE);
		hash = g_malloc ((SHA384_DIGEST_SIZE * 2) + 1);
	}
	
	else
	{
		digest = g_malloc (SHA512_DIGEST_SIZE);
		hash = g_malloc ((SHA512_DIGEST_SIZE * 2) + 1);
	}
	
	if (digest == NULL)
	{
		g_printerr ("sha2: error during memory allocation\n");
		return;
	}
	
	if (hash == NULL)
	{
		g_printerr ("sha2: error during memory allocation\n");
		g_free (digest);
		return;
	}
	
	fd = g_open (hash_var->filename, O_RDONLY | O_NOFOLLOW);
	if (fd == -1)
	{
		g_printerr ("sha2: %s\n", g_strerror (errno));
		return;
	}
  	
  	fileSize = get_file_size (hash_var->filename);
  	
  	if (bit == 256)
		sha256_init (&ctx256);
		
	else if (bit == 384)
		sha384_init (&ctx384);
	
	else
		sha512_init (&ctx512);
		
	if (fileSize < BUF_FILE)
	{
		fAddr = mmap (NULL, fileSize, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if (fAddr == MAP_FAILED)
		{
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (digest);
			g_free (hash);
			g_close (fd, &err);
			return;
		}
		if (bit == 256)
			sha256_update (&ctx256, fileSize, fAddr);
		
		else if (bit == 384)
			sha384_update (&ctx384, fileSize, fAddr);
		
		else
			sha512_update (&ctx512, fileSize, fAddr);
			
		retVal = munmap (fAddr, fileSize);
		if (retVal == -1)
		{
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (digest);
			g_free (hash);
			g_close (fd, &err);
			return;
		}
		goto nowhile;
	}
	
	while (fileSize > doneSize)
	{
		fAddr = mmap (NULL, BUF_FILE, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
		if (fAddr == MAP_FAILED)
		{
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (digest);
			g_free (hash);
			g_close (fd, &err);
			return;
		}
		
		if (bit == 256)
			sha256_update(&ctx256, BUF_FILE, fAddr);
		
		else if (bit == 384)
			sha384_update(&ctx384, BUF_FILE, fAddr);
		
		else
			sha512_update(&ctx512, BUF_FILE, fAddr);
		
		doneSize += BUF_FILE;
		diff = fileSize - doneSize;
		offset += BUF_FILE;
		
		if (diff < BUF_FILE && diff > 0)
		{
			fAddr = mmap (NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if (fAddr == MAP_FAILED)
			{
				g_printerr ("sha2: %s\n", g_strerror (errno));
				g_free (digest);
				g_free (hash);
				g_close (fd, &err);
				return;
			}
			
			if (bit == 256)
				sha256_update (&ctx256, diff, fAddr);
				
			else if (bit == 384)
				sha384_update (&ctx384, BUF_FILE, fAddr);
			
			else
				sha512_update (&ctx512, diff, fAddr);
				
			retVal = munmap(fAddr, diff);
			if(retVal == -1){
				g_printerr ("sha2: %s\n", g_strerror (errno));
				g_free (digest);
				g_free (hash);
				g_close (fd, &err);
				return;
			}
			break;
		}
		
		retVal = munmap(fAddr, BUF_FILE);
		if(retVal == -1)
		{
			g_printerr ("sha2: %s\n", g_strerror (errno));
			g_free (digest);
			g_free (hash);
			g_close (fd, &err);
			return;
		}
	}

	nowhile:
	if (bit == 256)
	{
		sha256_digest(&ctx256, SHA256_DIGEST_SIZE, digest);
		for (i = 0; i < SHA256_DIGEST_SIZE; i++)
			g_sprintf (hash+(i*2), "%02x", digest[i]);

		hash[SHA256_DIGEST_SIZE * 2] = '\0';
		gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[3]), hash);
		g_hash_table_insert (hash_var->hash_table, hash_var->key[3], strdup(hash));		
	}
	else if (bit == 384)
	{
		sha384_digest(&ctx384, SHA384_DIGEST_SIZE, digest);
		for (i = 0; i < SHA384_DIGEST_SIZE; i++)
			g_sprintf (hash+(i*2), "%02x", digest[i]);

		hash[SHA384_DIGEST_SIZE * 2] = '\0';
		gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[5]), hash);
		g_hash_table_insert (hash_var->hash_table, hash_var->key[5], strdup (hash));		
	}
	else
	{
		sha512_digest(&ctx512, SHA512_DIGEST_SIZE, digest);
		for (i = 0; i < SHA512_DIGEST_SIZE; i++)
			g_sprintf (hash+(i*2), "%02x", digest[i]);

		hash[SHA512_DIGEST_SIZE * 2] = '\0';
		gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[7]), hash);
		g_hash_table_insert (hash_var->hash_table, hash_var->key[7], strdup (hash));		
	}

 	
	g_close (fd, &err);
	g_free (digest);
	g_free (hash);
	
	fine:
	return;
}
