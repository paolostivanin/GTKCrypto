#include <gtk/gtk.h>
#include "gtkcrypto.h"


void
show_message_dialog (GtkWidget *parent,
                     const gchar *message,
                     GtkMessageType message_type)
{
    GtkWidget *dialog;

    if (parent == NULL)
        dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_MODAL, message_type, GTK_BUTTONS_OK,
                                         "%s", message);
    else
        dialog = gtk_message_dialog_new (GTK_WINDOW (parent), GTK_DIALOG_MODAL, message_type, GTK_BUTTONS_OK,
                                         "%s", message);

    gtk_dialog_run (GTK_DIALOG (dialog));

    gtk_widget_destroy (dialog);
}