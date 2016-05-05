#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gi18n.h>
#include <sys/mman.h>
#include "gtkcrypto.h"

//mode = 0 encrypt, mode = 1 decrypt

guchar
*calculate_hmac (const gchar *filename, const guchar *key, gsize keylen, goffset fileSize) {
	gint fd, retVal;
	gchar *fAddr;
	gsize fSize, doneSize = 0, diff = 0;
	goffset offset = 0;
	GError *err = NULL;

	fSize = (gsize) fileSize;
	
	fd = g_open (filename, O_RDONLY | O_NOFOLLOW);
	if (fd == -1) {
		g_printerr ("calculate_hmac: %s\n", g_strerror(errno));
		return (guchar *)1;
	}
  	  	
	gcry_md_hd_t hd;
	gcry_md_open (&hd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey (hd, key, keylen);
	if (fSize < BUF_FILE) {
		fAddr = mmap (NULL, fSize, PROT_READ, MAP_SHARED, fd, 0);
		if (fAddr == MAP_FAILED) {
			g_printerr ("calculate_hmac: %s\n", g_strerror(errno));
			return (guchar *)1;
		}
		gcry_md_write (hd, fAddr, fSize);
		retVal = munmap (fAddr, fSize);
		if (retVal == -1) {
			g_printerr ("calculate_hmac: --> munmap error");
			return (guchar *)1;
		}
		goto nowhile;
	}

	while (fSize > doneSize) {
		fAddr = mmap (NULL, BUF_FILE, PROT_READ, MAP_SHARED, fd, offset);
		if (fAddr == MAP_FAILED) {
			g_printerr ("calculate_hmac: %s\n", g_strerror(errno));
			return (guchar *)1;
		}

		gcry_md_write (hd, fAddr, BUF_FILE);
		doneSize += BUF_FILE;
		diff = fSize - doneSize;
		offset += BUF_FILE;

		if (diff > 0 && diff < BUF_FILE) {
			fAddr = mmap (NULL, diff, PROT_READ, MAP_SHARED, fd, offset);
			if (fAddr == MAP_FAILED) {
				g_printerr ("calculate_hmac:  %s\n", g_strerror(errno));
				return (guchar *)1;
			}

			gcry_md_write (hd, fAddr, diff);
			retVal = munmap (fAddr, diff);
			if (retVal == -1) {
				g_printerr ("calculate_hmac: --> munmap ");
				return (guchar *)1;
			}
			break;
		}
		retVal = munmap (fAddr, BUF_FILE);
		if (retVal == -1) {
			g_printerr ("calculate_hmac: --> munmap ");
			return (guchar *)1;
		}
	}

	nowhile:
	g_close (fd, &err);
	gcry_md_final (hd);
	guchar *tmp_hmac = gcry_md_read (hd, GCRY_MD_SHA512);
 	guchar *hmac = g_malloc (SHA512_DIGEST_SIZE);
 	memcpy (hmac, tmp_hmac, SHA512_DIGEST_SIZE);
	gcry_md_close (hd);
	
	return hmac;
}
