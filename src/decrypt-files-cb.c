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
    decrypt_widgets->first_run = TRUE;

    decrypt_widgets->files_list = choose_file (decrypt_widgets->main_window, "Choose file(s) to decrypt", TRUE);
    if (decrypt_widgets->files_list == NULL) {
        g_free (decrypt_widgets);
        return;
    }

    decrypt_widgets->dialog = create_dialog (decrypt_widgets->main_window, "dec_dialog", "Decrypt file");
    decrypt_widgets->cancel_btn = gtk_button_new_with_label ("Cancel");
    decrypt_widgets->ok_btn = gtk_button_new_with_label ("OK");
    gtk_widget_set_size_request (decrypt_widgets->dialog, 600, -1);

    decrypt_widgets->entry_pwd = gtk_entry_new ();
    gtk_entry_set_placeholder_text (GTK_ENTRY (decrypt_widgets->entry_pwd), "Type password...");
    gtk_entry_set_visibility (GTK_ENTRY (decrypt_widgets->entry_pwd), FALSE);
    gtk_widget_set_hexpand (decrypt_widgets->entry_pwd, TRUE);

    decrypt_widgets->ck_btn_delete = gtk_check_button_new_with_label ("Delete encrypted file");

    decrypt_widgets->message_label = gtk_label_new ("");

    decrypt_widgets->spinner = create_spinner ();

    GtkWidget *grid = gtk_grid_new ();
    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_attach (GTK_GRID (grid), decrypt_widgets->entry_pwd, 0, 0, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), decrypt_widgets->ck_btn_delete, 0, 1, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), decrypt_widgets->message_label, 0, 2, 2, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), decrypt_widgets->spinner, decrypt_widgets->message_label, GTK_POS_RIGHT, 1, 1);

    GtkWidget *hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_end (GTK_BOX(hbox), decrypt_widgets->ok_btn, TRUE, TRUE, 0);
    gtk_box_pack_end (GTK_BOX(hbox), decrypt_widgets->cancel_btn, TRUE, TRUE, 0);
    gtk_grid_attach (GTK_GRID (grid), hbox, 1, 4, 1, 1);

    gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (GTK_DIALOG (decrypt_widgets->dialog))), grid);

    gtk_widget_show_all (decrypt_widgets->dialog);

    gtk_widget_hide (decrypt_widgets->spinner);

    g_signal_connect (decrypt_widgets->entry_pwd, "activate", G_CALLBACK (prepare_multi_decryption_cb), decrypt_widgets);
    g_signal_connect (decrypt_widgets->ok_btn, "clicked", G_CALLBACK (prepare_multi_decryption_cb), decrypt_widgets);
    g_signal_connect (decrypt_widgets->cancel_btn, "clicked", G_CALLBACK (cancel_clicked_cb), decrypt_widgets);

    g_timeout_add (500, check_tp, decrypt_widgets);

    gtk_dialog_run (GTK_DIALOG (decrypt_widgets->dialog));
}


static gboolean
check_tp (gpointer data)
{
    DecryptWidgets *widgets = (DecryptWidgets *)data;
    if (widgets->running_threads == 0 && widgets->first_run == FALSE) {
        g_thread_pool_free (widgets->thread_pool, FALSE, TRUE);
        show_message_dialog (widgets->main_window, "File(s) successfully decrypted.", GTK_MESSAGE_INFO);
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
    decrypt_file (filename, thread_data->pwd);
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

    gtk_widget_destroy (decrypt_widgets->dialog);

    g_slist_free_full (decrypt_widgets->files_list, g_free);

    g_free (decrypt_widgets);
}