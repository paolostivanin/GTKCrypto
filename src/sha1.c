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
#include <nettle/sha1.h>
#include <sys/mman.h>
#include "polcrypt.h"
 

static goffset get_file_size (const gchar *);


void
compute_sha1 (struct hashWidget_t *HashWidget)
{
   	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (HashWidget->hashCheck[1])))
   	{
		gtk_entry_set_text(GTK_ENTRY(HashWidget->hashEntry[1]), "");
		goto fine;
	}
	else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (HashWidget->hashEntry[1])), -1) == 40)
		goto fine;
	
	gpointer ptr = g_hash_table_lookup (HashWidget->hashTable, HashWidget->key[1]);
	if (ptr != NULL)
	{
		gtk_entry_set_text (GTK_ENTRY (HashWidget->hashEntry[1]), (gchar *)g_hash_table_lookup (HashWidget->hashTable, HashWidget->key[1]));
		goto fine;
	}

	struct sha1_ctx ctx;
	guint8 digest[SHA1_DIGEST_SIZE];
	gint fd, i, retVal;
	goffset fileSize = 0, doneSize = 0, diff = 0, offset = 0;
	gchar hash[41];
	guint8 *fAddr;
	GError *err = NULL;
	
	fd = g_open (HashWidget->filename, O_RDONLY | O_NOFOLLOW);
	if(fd == -1)
	{
		g_printerr ("sha1: %s\n", g_strerror (errno));
		return;
	}
  
  	fileSize = get_file_size (HashWidget->filename);
       
	sha1_init(&ctx);

	if (fileSize < BUF_FILE)
	{
		fAddr = mmap (NULL, fileSize, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if (fAddr == MAP_FAILED)
		{
			g_printerr ("sha1: %s\n", g_strerror (errno));
			return;
		}
		sha1_update (&ctx, fileSize, fAddr);
		retVal = munmap (fAddr, fileSize);
		if (retVal == -1)
		{
			g_printerr ("sha1: munmap error");
			return;
		}
		goto nowhile;
	}

	while (fileSize > doneSize)
	{
		fAddr = mmap (NULL, BUF_FILE, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
		if (fAddr == MAP_FAILED)
		{
			g_printerr ("sha1: %s\n", g_strerror (errno));
			return;
		}
		sha1_update (&ctx, BUF_FILE, fAddr);
		doneSize += BUF_FILE;
		diff = fileSize - doneSize;
		offset += BUF_FILE;
		if (diff < BUF_FILE && diff > 0)
		{
			fAddr = mmap (NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if (fAddr == MAP_FAILED)
			{
				g_printerr ("sha1: %s\n", g_strerror (errno));
				return;
			}
			sha1_update (&ctx, diff, fAddr);
			retVal = munmap (fAddr, diff);
			if (retVal == -1)
			{
				g_printerr ("sha1: munmap error");
				return;
			}
			break;
		}
		retVal = munmap (fAddr, BUF_FILE);
		if (retVal == -1)
		{
			g_printerr ("sha1: munmap error");
			return;
		}
	}
	
	nowhile:	
	sha1_digest (&ctx, SHA1_DIGEST_SIZE, digest);
 	for (i=0; i<20; i++)
 		sprintf (hash+(i*2), "%02x", digest[i]);
 		
 	hash[40] = '\0';
 	gtk_entry_set_text (GTK_ENTRY (HashWidget->hashEntry[1]), hash);
 	g_hash_table_insert (HashWidget->hashTable, HashWidget->key[1], strdup(hash));
 	
	g_close(fd, &err);
	
	fine:
	return;
}


static goffset
get_file_size (const gchar *filePath)
{
	GFileInfo *info;
	GFile *file;
	GError *error = NULL;
	const gchar *attributes = "standard::*";
	GFileQueryInfoFlags flags = G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS;
	GCancellable *cancellable = NULL;
	goffset fileSize;

	file = g_file_new_for_path (filePath);
	info = g_file_query_info (file, attributes, flags, cancellable, &error);
	fileSize = g_file_info_get_size (info);

	g_object_unref(file);
	
	return fileSize;
}
