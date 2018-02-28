#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include "gtkcrypto.h"
#include "common-widgets.h"
#include "decrypt-files-cb.h"

typedef struct decrypt_file_widgets_t {
    GtkWidget *main_window;
    GtkWidget *dialog;
    GtkWidget *entry_pwd;
    GtkWidget *ck_btn_delete;
    GtkWidget *cancel_btn;
    GtkWidget *ok_btn;
    GtkWidget *spinner;
    GtkWidget *message_label;
    GSList    *files_list;
    GThreadPool *thread_pool;
    guint running_threads;
    guint files_not_decrypted;
    guint source_id;
    gboolean first_run;
} DecryptWidgets;

typedef struct dec_thread_data_t {
    GMutex mutex;
    GtkWidget *dialog;
    GtkWidget *spinner;
    guint list_len;
    const gchar *pwd;
    gboolean delete_file;
    DecryptWidgets *widgets;
} ThreadData;

static void     cancel_clicked_cb           (GtkWidget *btn,
                                             gpointer   user_data);

static gboolean check_tp                    (gpointer data);

static void     prepare_multi_decryption_cb (GtkWidget      *widget,
                                             DecryptWidgets *data);

static void     exec_thread                 (gpointer data,
                                             gpointer user_data);


void
decrypt_files_cb (GtkWidget *btn __attribute__((unused)),
                  gpointer   user_data)
{
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

    GtkBuilder *builder = gtk_builder_new_from_file ("../src/ui/widgets.ui");
    decrypt_widgets->dialog = GTK_WIDGET (gtk_builder_get_object (builder, "dec_pwd_diag"));
    decrypt_widgets->ok_btn = GTK_WIDGET (gtk_builder_get_object (builder, "ok_btn_dec_pwd_diag"));
    decrypt_widgets->cancel_btn = GTK_WIDGET (gtk_builder_get_object (builder, "cancel_btn_dec_pwd_diag"));
    decrypt_widgets->entry_pwd = GTK_WIDGET (gtk_builder_get_object (builder, "dec_pwd_entry"));
    decrypt_widgets->message_label = GTK_WIDGET (gtk_builder_get_object (builder, "dec_label"));
    decrypt_widgets->spinner = GTK_WIDGET (gtk_builder_get_object (builder, "dec_spinner"));
    decrypt_widgets->ck_btn_delete = GTK_WIDGET (gtk_builder_get_object (builder, "check_btn_delfile"));
    g_object_unref (builder);

    gtk_widget_show_all (decrypt_widgets->dialog);
    gtk_widget_hide (decrypt_widgets->spinner);

    g_signal_connect (decrypt_widgets->entry_pwd, "activate", G_CALLBACK (prepare_multi_decryption_cb), decrypt_widgets);
    g_signal_connect (decrypt_widgets->ok_btn, "clicked", G_CALLBACK (prepare_multi_decryption_cb), decrypt_widgets);
    g_signal_connect (decrypt_widgets->cancel_btn, "clicked", G_CALLBACK (cancel_clicked_cb), decrypt_widgets);

    decrypt_widgets->source_id = g_timeout_add (500, check_tp, decrypt_widgets);

    gtk_dialog_run (GTK_DIALOG (decrypt_widgets->dialog));
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
    thread_data->pwd = gtk_entry_get_text (GTK_ENTRY (data->entry_pwd));
    thread_data->delete_file = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data->ck_btn_delete));
    thread_data->widgets = data;

    gtk_label_set_label (GTK_LABEL (data->message_label), "Decrypting file(s)...");
    gtk_widget_show (thread_data->spinner);
    start_spinner (thread_data->spinner);

    change_widgets_sensitivity (4, FALSE, &data->ok_btn, &data->cancel_btn, &data->entry_pwd, &data->ck_btn_delete);

    g_mutex_init (&thread_data->mutex);

    data->thread_pool = g_thread_pool_new (exec_thread, thread_data, g_get_num_processors (), TRUE, NULL);
    for (guint i = 0; i < thread_data->list_len; i++) {
        g_thread_pool_push (data->thread_pool, g_slist_nth_data (data->files_list, i), NULL);
    }
    gtk_dialog_response (GTK_DIALOG (data->dialog), GTK_RESPONSE_DELETE_EVENT);
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

    // TODO log to file (filename OK, filename NOT OK, ecc) instead and display it at the end
    gpointer ret = decrypt_file (filename, thread_data->pwd);
    if (ret != NULL) {
        g_mutex_lock (&thread_data->mutex);
        thread_data->widgets->files_not_decrypted++;
        g_mutex_unlock (&thread_data->mutex);
        // TODO deal with error
    }
    if (thread_data->delete_file) {
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

    gtk_widget_destroy (decrypt_widgets->dialog);

    g_slist_free_full (decrypt_widgets->files_list, g_free);

    g_free (decrypt_widgets);
}