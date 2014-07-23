#include <gtk/gtk.h>
#include <glib.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include <libnotify/notify.h>
#include "polcrypt.h"

guchar *calculate_hmac(const gchar *, const guchar *, gsize, gint);
gint delete_input_file(const gchar *, gsize);
gint check_pkcs7(guchar *, guchar *);
static void send_notification(const gchar *, const gchar *);
goffset get_file_size (const gchar *);

gint
crypt_file(struct widget_t *Widget,
	   gint mode)
{
	goffset fileSize;
	fileSize = get_file_size (Widget->filename);
}	

goffset
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
