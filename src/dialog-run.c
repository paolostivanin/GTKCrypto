#include <gtk/gtk.h>
#include <gio/gio.h>

#include "gtkcrypto.h"

typedef struct {
    gulong close_request_id;
    gulong destroy_id;
} DialogRunData;

typedef struct {
    GtkWindow *dialog;
    gint response;
} DialogFinishData;

static void dialog_complete (GtkWindow *dialog,
                             gint       response);

static void dialog_cleanup (GtkWindow *dialog);

static gboolean dialog_finish_response_invoke (gpointer user_data);

static gboolean
dialog_close_request_cb (GtkWindow *dialog,
                         gpointer   user_data __attribute__((unused)))
{
    gpointer response = g_object_get_data (G_OBJECT (dialog), "dialog-response");

    if (response == NULL) {
        response = GINT_TO_POINTER (GTK_RESPONSE_DELETE_EVENT);
    }

    dialog_complete (dialog, GPOINTER_TO_INT (response));
    return FALSE;
}

static void
dialog_destroy_cb (GtkWidget *dialog,
                   gpointer   user_data __attribute__((unused)))
{
    gpointer response = g_object_get_data (G_OBJECT (dialog), "dialog-response");

    if (response == NULL) {
        response = GINT_TO_POINTER (GTK_RESPONSE_DELETE_EVENT);
    }

    dialog_complete (GTK_WINDOW (dialog), GPOINTER_TO_INT (response));
}

void
dialog_set_response (GtkWindow *dialog,
                     gint       response)
{
    g_object_set_data (G_OBJECT (dialog), "dialog-response", GINT_TO_POINTER (response));
}

void
dialog_finish_response (GtkWindow *dialog,
                        gint       response)
{
    if (g_main_context_is_owner (g_main_context_default ())) {
        dialog_complete (dialog, response);
        return;
    }

    DialogFinishData *data = g_new0 (DialogFinishData, 1);
    data->dialog = g_object_ref (dialog);
    data->response = response;
    g_main_context_invoke (NULL, dialog_finish_response_invoke, data);
}

void
dialog_run_async (GtkWindow           *dialog,
                  GCancellable        *cancellable,
                  GAsyncReadyCallback  callback,
                  gpointer             user_data)
{
    DialogRunData *data = g_new0 (DialogRunData, 1);
    GTask *task = g_task_new (dialog, cancellable, callback, user_data);

    dialog_set_response (dialog, GTK_RESPONSE_NONE);
    g_object_set_data (G_OBJECT (dialog), "dialog-task", task);

    data->close_request_id = g_signal_connect (dialog, "close-request",
                                               G_CALLBACK (dialog_close_request_cb), data);
    data->destroy_id = g_signal_connect (dialog, "destroy",
                                         G_CALLBACK (dialog_destroy_cb), data);
    g_object_set_data (G_OBJECT (dialog), "dialog-run-data", data);

    gtk_window_present (dialog);
}

gint
dialog_run_finish (GtkWindow   *dialog,
                   GAsyncResult *result,
                   GError     **error)
{
    g_return_val_if_fail (g_task_is_valid (result, dialog), GTK_RESPONSE_NONE);

    return g_task_propagate_int (G_TASK (result), error);
}

static void
dialog_complete (GtkWindow *dialog,
                 gint       response)
{
    GTask *task = g_object_steal_data (G_OBJECT (dialog), "dialog-task");

    if (task == NULL) {
        return;
    }

    dialog_set_response (dialog, response);
    dialog_cleanup (dialog);
    g_task_return_int (task, response);
    g_object_unref (task);
}

static void
dialog_cleanup (GtkWindow *dialog)
{
    DialogRunData *data = g_object_steal_data (G_OBJECT (dialog), "dialog-run-data");

    if (data == NULL) {
        return;
    }

    if (data->close_request_id != 0) {
        g_signal_handler_disconnect (dialog, data->close_request_id);
    }
    if (data->destroy_id != 0) {
        g_signal_handler_disconnect (dialog, data->destroy_id);
    }
    g_free (data);
}

static gboolean
dialog_finish_response_invoke (gpointer user_data)
{
    DialogFinishData *data = user_data;

    dialog_complete (data->dialog, data->response);
    g_object_unref (data->dialog);
    g_free (data);
    return G_SOURCE_REMOVE;
}
