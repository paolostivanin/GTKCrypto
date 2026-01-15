#include <gtk/gtk.h>

#include "gtkcrypto.h"

typedef struct {
    GMainLoop *loop;
    GSList *files;
} FileDialogData;

static void
file_dialog_single_cb (GObject      *source_object,
                       GAsyncResult *result,
                       gpointer      user_data)
{
    FileDialogData *data = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source_object);
    GFile *file = gtk_file_dialog_open_finish (dialog, result, NULL);

    if (file != NULL) {
        gchar *path = g_file_get_path (file);
        if (path != NULL) {
            data->files = g_slist_append (data->files, path);
        }
        g_object_unref (file);
    }

    g_main_loop_quit (data->loop);
}

static void
file_dialog_multiple_cb (GObject      *source_object,
                         GAsyncResult *result,
                         gpointer      user_data)
{
    FileDialogData *data = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source_object);
    GListModel *files = gtk_file_dialog_open_multiple_finish (dialog, result, NULL);

    if (files != NULL) {
        guint n_files = g_list_model_get_n_items (files);
        for (guint i = 0; i < n_files; i++) {
            GFile *file = g_list_model_get_item (files, i);
            gchar *path = g_file_get_path (file);
            if (path != NULL) {
                data->files = g_slist_append (data->files, path);
            }
            g_object_unref (file);
        }
        g_object_unref (files);
    }

    g_main_loop_quit (data->loop);
}

GSList *
choose_file (GtkWidget      *main_window,
             const gchar    *title,
             gboolean        select_multiple)
{
    FileDialogData data = {0};
    GtkFileDialog *dialog = gtk_file_dialog_new ();

    gtk_file_dialog_set_title (dialog, title);

    data.loop = g_main_loop_new (NULL, FALSE);
    data.files = NULL;

    if (select_multiple == TRUE) {
        gtk_file_dialog_open_multiple (dialog, GTK_WINDOW (main_window), NULL,
                                       file_dialog_multiple_cb, &data);
    } else {
        gtk_file_dialog_open (dialog, GTK_WINDOW (main_window), NULL,
                              file_dialog_single_cb, &data);
    }

    g_main_loop_run (data.loop);
    g_main_loop_unref (data.loop);
    g_object_unref (dialog);

    return data.files;
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
