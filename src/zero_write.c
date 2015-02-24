#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include "polcrypt.h"

gint
zero_write (	gint file,
		gsize file_size,
		gint isBigger)
{
	if (isBigger  == 0)
	{
		guchar zero_buf[file_size];
		memset (zero_buf, 0, sizeof (zero_buf));
		if (write (file, zero_buf, sizeof (zero_buf)) == -1)
			g_printerr ("zero_write write: %s\n", g_strerror (errno));
		
		if (fsync (file) == -1)
			g_printerr ("zero_write fsync: %s\n", g_strerror(errno));
			
		return 0;
	}
	else
	{
		guchar zero_buf[BUFSIZE];
		memset (zero_buf, 0, sizeof (zero_buf));
		gsize done_size = 0, writeBytes = 0;
		while (file_size > done_size)
		{
			writeBytes = write (file, zero_buf, sizeof (zero_buf));
			done_size += writeBytes;
			if ((file_size-done_size) > 0 && (file_size-done_size) < BUFSIZE)
			{
				if (write (file, zero_buf, (file_size-done_size)) == -1)
					g_printerr ("zero_write write: %s\n", g_strerror (errno));
				if (fsync (file) == -1)
					g_printerr ("zero_write fsync: %s\n", g_strerror (errno));

				break;
			}
		}
		return 0;
	}
}
