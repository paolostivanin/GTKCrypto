#include <gtk/gtk.h>
#include "gtkcrypto.h"
#include "common-widgets.h"
#include "encrypt-cb-common.h"

static gpointer exec_thread (gpointer);

static void cancel_clicked_cb (GtkWidget *, gpointer);


void
encrypt_multiple_files_dialog (EncryptWidgets *encrypt_widgets)
{
    encrypt_widgets->multi_files = TRUE;
    // TODO not complete. Find a way to add scrolled window, spinner, labels (filenames) and thread all!
    do_dialog (encrypt_widgets);

    GtkWidget *grid = gtk_grid_new ();
    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_attach (GTK_GRID (grid), encrypt_widgets->entry_pwd, 0, 0, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), encrypt_widgets->entry_pwd_retype, 0, 1, 2, 1);

    GtkWidget *hbox = create_hbox (encrypt_widgets);
    gtk_grid_attach (GTK_GRID (grid), hbox, 1, 2, 1, 1);

    gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (GTK_DIALOG (encrypt_widgets->dialog))), grid);

    gtk_widget_show_all (encrypt_widgets->dialog);

    g_signal_connect (encrypt_widgets->entry_pwd_retype, "activate", G_CALLBACK (entry_activated_cb), encrypt_widgets);
    g_signal_connect (encrypt_widgets->ok_btn, "clicked", G_CALLBACK (entry_activated_cb), encrypt_widgets);
    g_signal_connect (encrypt_widgets->cancel_btn, "clicked", G_CALLBACK (cancel_clicked_cb), encrypt_widgets);

    gint result = gtk_dialog_run (GTK_DIALOG (encrypt_widgets->dialog));
    switch (result) {
        case GTK_RESPONSE_DELETE_EVENT:
            if (encrypt_widgets->enc_thread != NULL) {
                gpointer msg = g_thread_join (encrypt_widgets->enc_thread);
                if (msg != NULL) {
                    show_message_dialog (encrypt_widgets->main_window, (gchar *) msg, GTK_MESSAGE_ERROR);
                    g_free (msg);
                }
            }
            gtk_widget_destroy (encrypt_widgets->dialog);
            g_slist_free_full (encrypt_widgets->files_list, g_free);
            g_free (encrypt_widgets);
            break;
        default:
            break;
    }
}


void
prepare_multi_encryption (const gchar *algo, const gchar *algo_mode, EncryptWidgets *data)
{
    ThreadData *thread_data = g_new0 (ThreadData, 1);

    thread_data->dialog = data->dialog;
    thread_data->spinner = data->spinner;
    thread_data->message_label = data->message_label;
    thread_data->algo_btn_name = algo;
    thread_data->algo_mode_btn_name = algo_mode;
    thread_data->filename = data->filename;
    thread_data->pwd = gtk_entry_get_text (GTK_ENTRY (data->entry_pwd));

    gtk_widget_show (thread_data->spinner);
    start_spinner (thread_data->spinner);

    change_widgets_sensitivity (4, FALSE, &data->ok_btn, &data->cancel_btn, &data->entry_pwd, &data->entry_pwd_retype);

    data->enc_thread = g_thread_new (NULL, exec_thread, thread_data);
}


static gpointer
exec_thread (gpointer user_data)
{
    ThreadData *data = user_data;

    gchar *basename = g_path_get_basename (data->filename);

    gchar *message = g_strconcat ("Encrypting <b>", basename, "</b>...", NULL);
    set_label_message (data->message_label, message);
    gpointer msg = encrypt_file (data->filename, data->pwd, data->algo_btn_name, data->algo_mode_btn_name);

    gtk_dialog_response (GTK_DIALOG (data->dialog), GTK_RESPONSE_DELETE_EVENT);

    multiple_free (3, (gpointer) &data, (gpointer) &basename, (gpointer) &message);

    g_thread_exit (msg);
}


static void
cancel_clicked_cb (GtkWidget *btn __attribute__((__unused__)), gpointer user_data)
{
    EncryptWidgets *encrypt_widgets = user_data;

    gtk_widget_destroy (encrypt_widgets->dialog);

    g_slist_free_full (encrypt_widgets->files_list, g_free);
    g_free (encrypt_widgets);
}
