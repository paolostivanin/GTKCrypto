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
#include "polcrypt.h"


static goffset get_file_size (const gchar *);


void
compute_sha3 (	struct hashWidget_t *HashWidget,
		gint bit)
{
	if (bit == 256)
	{
		if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (HashWidget->hashCheck[3])))
		{
			gtk_entry_set_text (GTK_ENTRY (HashWidget->hashEntry[3]), "");
			goto fine;
		}
		else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (HashWidget->hashEntry[3])), -1) == 64)
			goto fine;
	}
	else
	{
		if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (HashWidget->hashCheck[5])))
		{
			gtk_entry_set_text (GTK_ENTRY (HashWidget->hashEntry[5]), "");
			goto fine;
		}
		else if (g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (HashWidget->hashEntry[5])), -1) == 128)
			goto fine;		
	}
	
	guchar *digest;
	gchar *hash;
	GError *err = NULL;
	gint fd, i, retVal;
	goffset fileSize, doneSize = 0, diff = 0, offset = 0;
	guint8 *fAddr;
	
	struct sha3_256_ctx ctx256;
	struct sha3_512_ctx ctx512;
	
	if (bit == 256)
	{
		digest = g_malloc (SHA3_256_DIGEST_SIZE);
		hash = g_malloc (65);
	}
		
	else
	{
		digest = g_malloc (SHA3_512_DIGEST_SIZE);
		hash = g_malloc (129);
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
	
	fd = g_open (HashWidget->filename, O_RDONLY | O_NOFOLLOW);
	if (fd == -1)
	{
		g_printerr ("sha2: %s\n", g_strerror (errno));
		return;
	}
  	
  	fileSize = get_file_size (HashWidget->filename);
  	
  	if (bit == 256)
		sha3_256_init (&ctx256);
	else
		sha3_512_init (&ctx512);
		
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
			sha3_256_update (&ctx256, fileSize, fAddr);
		else
			sha3_512_update (&ctx512, fileSize, fAddr);
			
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
			sha3_256_update(&ctx256, BUF_FILE, fAddr);
		else
			sha3_512_update(&ctx512, BUF_FILE, fAddr);
		
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
				sha3_256_update(&ctx256, diff, fAddr);
			else
				sha3_512_update(&ctx512, diff, fAddr);
				
			retVal = munmap(fAddr, BUF_FILE);
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
		sha3_256_digest(&ctx256, SHA3_256_DIGEST_SIZE, digest);
		for(i=0; i<32; i++)
			g_sprintf (hash+(i*2), "%02x", digest[i]);

		hash[64] = '\0';
		gtk_entry_set_text (GTK_ENTRY (HashWidget->hashEntry[2]), hash);		
	}
	else
	{
		sha3_512_digest(&ctx512, SHA3_512_DIGEST_SIZE, digest);
		for(i=0; i<64; i++)
			g_sprintf (hash+(i*2), "%02x", digest[i]);

		hash[128] = '\0';
		gtk_entry_set_text (GTK_ENTRY (HashWidget->hashEntry[4]), hash);		
	}

 	
	g_close (fd, &err);
	g_free (digest);
	g_free (hash);
	
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
