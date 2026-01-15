#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include "gtkcrypto.h"
#include "decrypt-files-cb.h"

static gboolean check_tp                    (gpointer data);

static void     prepare_multi_decryption_cb (GtkWidget      *widget,
                                             DecryptWidgets *data);

static void     exec_thread                 (gpointer data,
                                             gpointer user_data);

static void     cancel_clicked_cb           (GtkWidget *btn,
                                             gpointer   user_data);


void
decrypt_files_cb (GtkWidget *btn __attribute__((unused)),
                  gpointer   user_data)
{
    GtkBuilder *builder = get_builder_from_path (PARTIAL_PATH_TO_UI_FILE);
    if (builder == NULL) {
        return;
    }

    DecryptWidgets *decrypt_widgets = g_new0 (DecryptWidgets, 1);

    decrypt_widgets->main_window = (GtkWidget *)user_data;
    decrypt_widgets->running_threads = 0;
    decrypt_widgets->files_not_decrypted = 0;
    decrypt_widgets->first_run = TRUE;

    decrypt_widgets->files_list = choose_file (decrypt_widgets->main_window, "Choose file(s) to decrypt", TRUE);
    if (decrypt_widgets->files_list == NULL) {
        g_free (decrypt_widgets);
        return;
    }

    decrypt_widgets->dialog = GTK_WIDGET (gtk_builder_get_object (builder, "dec_pwd_diag"));
    decrypt_widgets->ok_btn = GTK_WIDGET (gtk_builder_get_object (builder, "ok_btn_dec_pwd_diag"));
    decrypt_widgets->cancel_btn = GTK_WIDGET (gtk_builder_get_object (builder, "cancel_btn_dec_pwd_diag"));
    decrypt_widgets->entry_pwd = GTK_WIDGET (gtk_builder_get_object (builder, "dec_pwd_entry"));
    decrypt_widgets->message_label = GTK_WIDGET (gtk_builder_get_object (builder, "dec_label"));
    decrypt_widgets->spinner = GTK_WIDGET (gtk_builder_get_object (builder, "dec_spinner"));
    decrypt_widgets->ck_btn_delete = GTK_WIDGET (gtk_builder_get_object (builder, "check_btn_delfile"));
    g_object_unref (builder);

    gtk_widget_set_visible (decrypt_widgets->spinner, FALSE);

    g_signal_connect (decrypt_widgets->entry_pwd, "activate", G_CALLBACK (prepare_multi_decryption_cb), decrypt_widgets);
    g_signal_connect (decrypt_widgets->ok_btn, "clicked", G_CALLBACK (prepare_multi_decryption_cb), decrypt_widgets);
    g_signal_connect (decrypt_widgets->cancel_btn, "clicked", G_CALLBACK (cancel_clicked_cb), decrypt_widgets);

    decrypt_widgets->source_id = g_timeout_add (500, check_tp, decrypt_widgets);

    run_dialog (GTK_WINDOW (decrypt_widgets->dialog));
}


static gboolean
check_tp (gpointer data)
{
    DecryptWidgets *widgets = (DecryptWidgets *)data;
    if (widgets->running_threads == 0 && widgets->first_run == FALSE) {
        g_thread_pool_free (widgets->thread_pool, FALSE, TRUE);
        guint list_len = g_slist_length (widgets->files_list);
        // TODO show failed files
        gchar *msg = g_strdup_printf ("%u/%u file(s) successfully decrypted.", list_len - widgets->files_not_decrypted, list_len);
        show_message_dialog (widgets->main_window, msg, GTK_MESSAGE_INFO);
        g_free (msg);
        cancel_clicked_cb (NULL, widgets);
        return FALSE;
    } else {
        return TRUE;
    }
}


void
prepare_multi_decryption_cb (GtkWidget      *widget __attribute__((unused)),
                             DecryptWidgets *data)
{
    ThreadData *thread_data = g_new0 (ThreadData, 1);
    thread_data->dialog = data->dialog;
    thread_data->spinner = data->spinner;
    thread_data->list_len = g_slist_length (data->files_list);
    thread_data->pwd = gtk_editable_get_text (GTK_EDITABLE (data->entry_pwd));
    thread_data->delete_file = gtk_check_button_get_active (GTK_CHECK_BUTTON (data->ck_btn_delete));
    thread_data->widgets = data;

    gtk_label_set_label (GTK_LABEL (data->message_label), "Decrypting file(s)...");
    gtk_widget_set_visible (thread_data->spinner, TRUE);
    start_spinner (thread_data->spinner);

    change_widgets_sensitivity (4, FALSE, &data->ok_btn, &data->cancel_btn, &data->entry_pwd, &data->ck_btn_delete);

    g_mutex_init (&thread_data->mutex);

    data->thread_pool = g_thread_pool_new (exec_thread, thread_data, (gint)g_get_num_processors (), TRUE, NULL);
    for (guint i = 0; i < thread_data->list_len; i++) {
        g_thread_pool_push (data->thread_pool, g_slist_nth_data (data->files_list, i), NULL);
    }
    dialog_finish_response (GTK_WINDOW (data->dialog), GTK_RESPONSE_DELETE_EVENT);
}


static void
exec_thread (gpointer data,
             gpointer user_data)
{
    const gchar *filename = (gchar *)data;
    ThreadData *thread_data = user_data;

    g_mutex_lock (&thread_data->mutex);
    thread_data->widgets->running_threads++;
    g_mutex_unlock (&thread_data->mutex);

    gpointer ret = decrypt_file (filename, thread_data->pwd);
    if (ret != NULL) {
        g_mutex_lock (&thread_data->mutex);
        thread_data->widgets->files_not_decrypted++;
        g_mutex_unlock (&thread_data->mutex);
    }
    if (thread_data->delete_file && ret == NULL) {
        g_unlink (filename);
    }
    g_mutex_lock (&thread_data->mutex);
    thread_data->widgets->running_threads--;
    thread_data->widgets->first_run = FALSE;
    g_mutex_unlock (&thread_data->mutex);
}


static void
cancel_clicked_cb (GtkWidget *btn __attribute__((unused)),
                   gpointer user_data)
{
    DecryptWidgets *decrypt_widgets = user_data;

    g_source_remove (decrypt_widgets->source_id);

    dialog_set_response (GTK_WINDOW (decrypt_widgets->dialog), GTK_RESPONSE_CANCEL);
    gtk_window_destroy (GTK_WINDOW (decrypt_widgets->dialog));

    g_slist_free_full (decrypt_widgets->files_list, g_free);

    g_free (decrypt_widgets);
}
