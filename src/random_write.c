#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <errno.h>
#include "polcrypt.h"

gint
random_write (	gint file,
		gint fileRand,
		gsize fSize,
		gint isBigger)
{
	if (isBigger == 0)
	{
		guchar bRand[fSize];
		read (fileRand, bRand, sizeof (bRand));
		write (file, bRand, sizeof (bRand));
		if (fsync (file) == -1)
		{
			g_printerr ("fsync: %s\n", g_strerror(errno));
			return -1;
		}
		return 0;
	}
	else
	{
		guchar bytesRandom[BUFSIZE];
		gsize doneSize = 0, writeBytes = 0;
		read (fileRand, bytesRandom, sizeof (bytesRandom));
		while (fSize > doneSize)
		{
			writeBytes = write (file, bytesRandom, sizeof (bytesRandom));
			doneSize += writeBytes;
			if ((fSize-doneSize) > 0 && (fSize-doneSize) < BUFSIZE)
			{
				read (fileRand, bytesRandom, sizeof (bytesRandom));
				write (file, bytesRandom, (fSize-doneSize));
				if (fsync (file) == -1)
				{
					g_printerr ("fsync: %s\n", g_strerror(errno));
					return -1;
				}
				break;
			}
		}
		return 0;
	}
}
