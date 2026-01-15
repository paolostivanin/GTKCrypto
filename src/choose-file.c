#include <gtk/gtk.h>
#include <gio/gio.h>

#include "gtkcrypto.h"

static void free_file_list (gpointer data);

static void
file_dialog_single_cb (GObject      *source_object,
                       GAsyncResult *result,
                       gpointer      user_data)
{
    GTask *task = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source_object);
    GError *error = NULL;
    GFile *file = gtk_file_dialog_open_finish (dialog, result, &error);
    GSList *files = NULL;

    if (error != NULL) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    if (file != NULL) {
        gchar *path = g_file_get_path (file);
        if (path != NULL) {
            files = g_slist_append (files, path);
        }
        g_object_unref (file);
    }

    g_task_return_pointer (task, files, free_file_list);
    g_object_unref (task);
}

static void
file_dialog_multiple_cb (GObject      *source_object,
                         GAsyncResult *result,
                         gpointer      user_data)
{
    GTask *task = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source_object);
    GError *error = NULL;
    GListModel *files_model = gtk_file_dialog_open_multiple_finish (dialog, result, &error);
    GSList *files = NULL;

    if (error != NULL) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    if (files_model != NULL) {
        guint n_files = g_list_model_get_n_items (files_model);
        for (guint i = 0; i < n_files; i++) {
            GFile *file = g_list_model_get_item (files_model, i);
            gchar *path = g_file_get_path (file);
            if (path != NULL) {
                files = g_slist_append (files, path);
            }
            g_object_unref (file);
        }
        g_object_unref (files_model);
    }

    g_task_return_pointer (task, files, free_file_list);
    g_object_unref (task);
}

void
choose_file_async (GtkWindow           *parent,
                   const gchar         *title,
                   gboolean             select_multiple,
                   GCancellable        *cancellable,
                   GAsyncReadyCallback  callback,
                   gpointer             user_data)
{
    GTask *task = g_task_new (parent, cancellable, callback, user_data);
    GtkFileDialog *dialog = gtk_file_dialog_new ();

    gtk_file_dialog_set_title (dialog, title);
    g_task_set_task_data (task, g_object_ref (dialog), g_object_unref);

    if (select_multiple == TRUE) {
        gtk_file_dialog_open_multiple (dialog, parent, cancellable,
                                       file_dialog_multiple_cb, task);
    } else {
        gtk_file_dialog_open (dialog, parent, cancellable,
                              file_dialog_single_cb, task);
    }

    g_object_unref (dialog);
}

GSList *
choose_file_finish (GtkWindow    *parent,
                    GAsyncResult *result,
                    GError      **error)
{
    g_return_val_if_fail (g_task_is_valid (result, parent), NULL);

    return g_task_propagate_pointer (G_TASK (result), error);
}

static void
free_file_list (gpointer data)
{
    g_slist_free_full (data, g_free);
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
