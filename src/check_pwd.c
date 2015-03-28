#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "gtkcrypto.h"


gint
check_pwd (	GtkWidget *first_pwd_entry,
		GtkWidget *second_pwd_entry)
{
	const gchar *pw1 = gtk_entry_get_text (GTK_ENTRY (first_pwd_entry));
	const gchar *pw2 = gtk_entry_get_text (GTK_ENTRY (second_pwd_entry));
	
	if (g_strcmp0 (pw1, pw2) != 0)
		return -1;
		
	else if (g_utf8_strlen (pw1, -1) < 8)
		return -2;

	else
		return 0;
}
