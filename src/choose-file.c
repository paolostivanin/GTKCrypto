#include <gtk/gtk.h>

gchar *
choose_file (GtkWidget *main_window)
{
    gchar *filename = NULL;
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Choose File", GTK_WINDOW (main_window),
                                                    GTK_FILE_CHOOSER_ACTION_OPEN,
                                                    "OK", GTK_RESPONSE_ACCEPT, "Cancel", GTK_RESPONSE_CANCEL,
                                                    NULL);
    gint result = gtk_dialog_run (GTK_DIALOG (dialog));
    switch (result) {
        case GTK_RESPONSE_ACCEPT:
            filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
            gtk_widget_destroy (dialog);
            break;
        case GTK_RESPONSE_CANCEL:
            gtk_widget_destroy (dialog);
        default:
            break;
    }

    return filename;
}