#include <gtk/gtk.h>

#include "common-widgets.h"
#include "gtkcrypto.h"

static void
message_dialog_ok_cb (GtkWidget *button __attribute__((unused)),
                      gpointer   user_data)
{
    GtkWindow *dialog = GTK_WINDOW (user_data);

    dialog_set_response (dialog, GTK_RESPONSE_OK);
    gtk_window_destroy (dialog);
}


void
show_message_dialog (GtkWidget *parent,
                     const gchar *message,
                     GtkMessageType message_type)
{
    GtkWidget *dialog = NULL;
    GtkWidget *content_area = NULL;
    GtkWidget *action_area = NULL;
    GtkWidget *label = NULL;
    GtkWidget *ok_btn = NULL;
    const gchar *title = "GTKCrypto";

    if (message_type == GTK_MESSAGE_ERROR) {
        title = "Error";
    } else if (message_type == GTK_MESSAGE_WARNING) {
        title = "Warning";
    } else if (message_type == GTK_MESSAGE_INFO) {
        title = "Information";
    }

    dialog = create_dialog (parent, "message_dialog", title);
    content_area = get_dialog_content_area (dialog);
    action_area = get_dialog_action_area (dialog);

    label = gtk_label_new (NULL);
    gtk_label_set_markup (GTK_LABEL (label), message);
    gtk_label_set_wrap (GTK_LABEL (label), TRUE);
    gtk_label_set_wrap_mode (GTK_LABEL (label), PANGO_WRAP_WORD_CHAR);
    gtk_widget_set_halign (label, GTK_ALIGN_START);
    gtk_box_append (GTK_BOX (content_area), label);

    ok_btn = gtk_button_new_with_label ("OK");
    gtk_box_append (GTK_BOX (action_area), ok_btn);
    g_signal_connect (ok_btn, "clicked", G_CALLBACK (message_dialog_ok_cb), dialog);

    run_dialog (GTK_WINDOW (dialog));
}
