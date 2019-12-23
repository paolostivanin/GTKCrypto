#include <gtk/gtk.h>


void
show_message_dialog (GtkWidget *parent,
                     const gchar *message,
                     GtkMessageType message_type)
{
    static GtkWidget *dialog = NULL;

    dialog = gtk_message_dialog_new (parent == NULL ? NULL : GTK_WINDOW(parent), GTK_DIALOG_MODAL, message_type, GTK_BUTTONS_OK, "%s", message);

    gtk_message_dialog_set_markup (GTK_MESSAGE_DIALOG(dialog), message);

    gtk_dialog_run (GTK_DIALOG(dialog));

    gtk_widget_destroy (dialog);
}