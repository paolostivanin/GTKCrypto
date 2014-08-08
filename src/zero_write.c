#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include "polcrypt.h"

gint
zero_write (	gint file,
		size_t fSize,
		gint isBigger)
{
	gint ret;
	
	if (isBigger  == 0)
	{
		guchar zBuf[fSize];
		memset (zBuf, 0, sizeof (zBuf));
		ret = write (file, zBuf, sizeof (zBuf));
		if (fsync (file) == -1)
		{
			g_printerr ("zero_write fsync: %s\n", g_strerror(errno));
			return -1;
		}
		return 0;
	}
	else
	{
		guchar zBuf[BUFSIZE];
		memset (zBuf, 0, sizeof (zBuf));
		gsize doneSize = 0, writeBytes = 0;
		while (fSize > doneSize)
		{
			writeBytes = write (file, zBuf, sizeof (zBuf));
			doneSize += writeBytes;
			if ((fSize-doneSize) > 0 && (fSize-doneSize) < BUFSIZE)
			{
				ret = write (file, zBuf, (fSize-doneSize));
				if (fsync (file) == -1)
				{
					g_printerr ("zero_write fsync: %s\n", g_strerror(errno));
					return -1;
				}
				break;
			}
		}
		return 0;
	}
}
