#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <errno.h>
#include "gtkcrypto.h"

gint random_write (gint, gint, gsize, gint);
gint zero_write (gint, gsize, gint);

gint
delete_input_file (	const gchar *filename,
			gsize fileSize)
{
	gint fd, fdRandom, ret;
	GError *err = NULL;
	
	fd = g_open (filename, O_WRONLY | O_NOFOLLOW);
	fdRandom = open ("/dev/random", O_RDONLY);
	if (fd == -1)
	{
		g_printerr ("Input file: %s\n", g_strerror (errno));
		return -1;
	}	
	if (fdRandom == -1)
	{
		g_printerr ("Random file: %s\n", g_strerror (errno));
		return -1;
	}
	
	if (fileSize < BUFSIZE)
	{
		random_write (fd, fdRandom, fileSize, 0);
		lseek (fd, 0, SEEK_SET);
		zero_write (fd, fileSize, 0);
	}
	else
	{
		random_write (fd, fdRandom, fileSize, 1);
		lseek (fd, 0, SEEK_SET);
		zero_write (fd, fileSize, 1);
	}
	
	ret = ftruncate( fd, 0);
	if (ret == -1)
		g_printerr ("ftruncate: %s\n", g_strerror (errno));
	
	if (fsync (fd) == -1)
	{
		g_printerr ("fsync: %s\n", g_strerror (errno));
		return -1;
	}
	
	g_close (fd, &err);
	g_close (fdRandom, &err);

	if (g_remove (filename) == -1)
	{
		g_printerr ("Input file remove: %s\n", g_strerror (errno));
		return -2;
	}
		
	return 0;
}
