#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "polcrypt.h"


void error_dialog (const gchar *message)
{
	GtkWidget *dialog;
	
	dialog = gtk_message_dialog_new (NULL,
					GTK_DIALOG_MODAL,
					GTK_MESSAGE_ERROR,
					GTK_BUTTONS_OK,
					"%s", message);
					
	gtk_dialog_run (GTK_DIALOG (dialog));
	
	gtk_widget_destroy (dialog);
}
