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
#include <sys/mman.h>
#include "polcrypt.h"


void
compute_whirlpool (	GtkWidget __attribute__((__unused__)) *bt,
			gpointer user_data)
{
	struct hash_vars *hash_var = user_data;
	
   	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_var->hash_check[9])))
   	{
		gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[9]), "");
		goto fine;
	}
	
	else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (hash_var->hash_entry[9])), -1) == 128)
		goto fine;
		
	gpointer ptr = g_hash_table_lookup (hash_var->hash_table, hash_var->key[9]);
	if (ptr != NULL)
	{
		gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[9]), (gchar *)g_hash_table_lookup (hash_var->hash_table, hash_var->key[9]));
		goto fine;
	}

	gint algo, i, fd, retVal;
	gchar hash[129];
	guint8 *fAddr;
	const gchar *name = gcry_md_algo_name(GCRY_MD_WHIRLPOOL);
	algo = gcry_md_map_name(name);
	goffset fileSize = 0, doneSize = 0, diff = 0, offset = 0;
	GError *err = NULL;

	fd = g_open (hash_var->filename, O_RDONLY | O_NOFOLLOW);
	if (fd == -1)
	{
		g_printerr ("whirlpool: %s\n", g_strerror (errno));
		return;
	}
  	
  	fileSize = get_file_size (hash_var->filename);

	gcry_md_hd_t hd;
	gcry_md_open(&hd, algo, 0);

	if (fileSize < BUF_FILE)
	{
		fAddr = mmap (NULL, fileSize, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if (fAddr == MAP_FAILED)
		{
			g_printerr ("whirlpool: %s\n", g_strerror (errno));
			return;
		}
		gcry_md_write (hd, fAddr, fileSize);
		retVal = munmap (fAddr, fileSize);
		if (retVal == -1)
		{
			g_printerr ("whirlpool: munmap error");
			return;
		}
		goto nowhile;
	}

	while (fileSize > doneSize)
	{
		fAddr = mmap (NULL, BUF_FILE, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
		if (fAddr == MAP_FAILED)
		{
			g_printerr ("whirlpool: %s\n", g_strerror (errno));
			return;
		}
		gcry_md_write (hd, fAddr, BUF_FILE);
		doneSize += BUF_FILE;
		diff = fileSize - doneSize;
		offset += BUF_FILE;
		if (diff < BUF_FILE && diff > 0)
		{
			fAddr = mmap (NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if (fAddr == MAP_FAILED)
			{
				g_printerr ("whirlpool: %s\n", g_strerror (errno));
				return;
			}
			gcry_md_write (hd, fAddr, diff);
			retVal = munmap (fAddr, diff);
			if (retVal == -1)
			{
				g_printerr ("whirlpool: munmap error");
				return;
			}
			break;
		}
		retVal = munmap (fAddr, BUF_FILE);
		if (retVal == -1)
		{
			g_printerr ("whirlpool: munmap error");
			return;
		}
	}
	
	nowhile:
	gcry_md_final (hd);
	guchar *whirlpool = gcry_md_read (hd, algo);
 	for (i=0; i<64; i++)
 		g_sprintf (hash+(i*2), "%02x", whirlpool[i]);
 	
 	hash[128] = '\0';
 	gtk_entry_set_text (GTK_ENTRY (hash_var->hash_entry[9]), hash);
 	g_hash_table_insert (hash_var->hash_table, hash_var->key[9], strdup(hash));
 	
	gcry_md_close (hd);
	g_close(fd, &err);
	
	fine:
	return;
}