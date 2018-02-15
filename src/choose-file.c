#include <gtk/gtk.h>

GSList *
choose_file (GtkWidget      *main_window,
             const gchar    *title,
             gboolean        select_multiple)
{
    GSList *data = NULL;
    GtkWidget *dialog = gtk_file_chooser_dialog_new (title, GTK_WINDOW (main_window),
                                                     GTK_FILE_CHOOSER_ACTION_OPEN,
                                                     "OK", GTK_RESPONSE_ACCEPT,
                                                     "Cancel", GTK_RESPONSE_CANCEL,
                                                     NULL);

    gtk_file_chooser_set_select_multiple (GTK_FILE_CHOOSER (dialog), select_multiple);

    gint result = gtk_dialog_run (GTK_DIALOG (dialog));
    switch (result) {
        case GTK_RESPONSE_ACCEPT:
            if (select_multiple == TRUE) {
                data = gtk_file_chooser_get_filenames (GTK_FILE_CHOOSER (dialog));
            } else {
                gchar *filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
                data = g_slist_append (data, filename);
            }
            gtk_widget_destroy (dialog);
            break;
        case GTK_RESPONSE_CANCEL:
            gtk_widget_destroy (dialog);
            break;
        default:
            break;
    }

    return data;
}


gchar *
get_filename_from_list (GSList *list)
{
    gchar *filename = NULL;
    if (list != NULL) {
        filename = g_strdup (g_slist_nth_data (list, 0));
    }
    g_slist_free_full (list, g_free);
    return filename;
}