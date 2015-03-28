#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include "gtkcrypto.h"

goffset
get_file_size (const gchar *file_path)
{
	GFileInfo *info;
	GFile *file;
	GError *error = NULL;
	const gchar *attributes = "standard::*";
	GFileQueryInfoFlags flags = G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS;
	GCancellable *cancellable = NULL;
	goffset file_size;

	file = g_file_new_for_path (file_path);
	info = g_file_query_info (file, attributes, flags, cancellable, &error);
	file_size = g_file_info_get_size (info);

	g_object_unref(file);
	
	return file_size;
}
