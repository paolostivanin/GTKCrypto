#include <gtk/gtk.h>

#include "gtkcrypto.h"

typedef struct {
    GMainLoop *loop;
} DialogRunData;

static gboolean
dialog_close_request_cb (GtkWindow *dialog,
                         gpointer   user_data)
{
    DialogRunData *data = user_data;
    gpointer response = g_object_get_data (G_OBJECT (dialog), "dialog-response");

    if (response == NULL) {
        dialog_set_response (dialog, GTK_RESPONSE_DELETE_EVENT);
    }

    g_main_loop_quit (data->loop);
    return FALSE;
}

static void
dialog_destroy_cb (GtkWidget *dialog,
                   gpointer   user_data)
{
    DialogRunData *data = user_data;

    g_main_loop_quit (data->loop);
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
    GMainLoop *loop = g_object_get_data (G_OBJECT (dialog), "dialog-loop");

    dialog_set_response (dialog, response);
    if (loop != NULL) {
        g_main_loop_quit (loop);
    }
}

gint
run_dialog (GtkWindow *dialog)
{
    DialogRunData data = {0};
    gpointer response = NULL;

    dialog_set_response (dialog, GTK_RESPONSE_NONE);

    data.loop = g_main_loop_new (NULL, FALSE);
    g_object_set_data (G_OBJECT (dialog), "dialog-loop", data.loop);
    g_signal_connect (dialog, "close-request", G_CALLBACK (dialog_close_request_cb), &data);
    g_signal_connect (dialog, "destroy", G_CALLBACK (dialog_destroy_cb), &data);

    gtk_window_present (GTK_WINDOW (dialog));
    g_main_loop_run (data.loop);

    g_object_set_data (G_OBJECT (dialog), "dialog-loop", NULL);
    response = g_object_get_data (G_OBJECT (dialog), "dialog-response");
    g_signal_handlers_disconnect_by_func (dialog, G_CALLBACK (dialog_close_request_cb), &data);
    g_signal_handlers_disconnect_by_func (dialog, G_CALLBACK (dialog_destroy_cb), &data);
    g_main_loop_unref (data.loop);

    return response == NULL ? GTK_RESPONSE_NONE : GPOINTER_TO_INT (response);
}
