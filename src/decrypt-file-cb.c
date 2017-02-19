#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include "gtkcrypto.h"
#include "common-widgets.h"
#include "decrypt-file-cb.h"

typedef struct decrypt_file_widgets_t {
    GtkWidget *main_window;
    GtkWidget *dialog;
    GtkWidget *entry_pwd;
    GtkWidget *ck_btn_delete;
    GtkWidget *cancel_btn;
    GtkWidget *ok_btn;
    GtkWidget *spinner;
    GtkWidget *message_label;
    gchar *filename;
    GThread *dec_thread;
} DecryptWidgets;

typedef struct dec_thread_data_t {
    GtkWidget *dialog;
    GtkWidget *spinner;
    GtkWidget *message_label;
    const gchar *filename;
    const gchar *pwd;
    gboolean delete_file;
} ThreadData;

static void cancel_clicked_cb (GtkWidget *, gpointer user_data);

static void prepare_decryption_cb (GtkWidget *, gpointer user_data);

static gpointer exec_thread (gpointer user_data);


void
decrypt_file_cb (GtkWidget *btn __attribute__((__unused__)),
                 gpointer user_data) {
    DecryptWidgets *decrypt_widgets = g_new0 (DecryptWidgets, 1);

    decrypt_widgets->main_window = user_data;
    decrypt_widgets->dec_thread = NULL;

    decrypt_widgets->filename = choose_file (decrypt_widgets->main_window, "Pick file to decrypt");

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

    g_signal_connect (decrypt_widgets->entry_pwd, "activate", G_CALLBACK (prepare_decryption_cb), decrypt_widgets);
    g_signal_connect (decrypt_widgets->ok_btn, "clicked", G_CALLBACK (prepare_decryption_cb), decrypt_widgets);
    g_signal_connect (decrypt_widgets->cancel_btn, "clicked", G_CALLBACK(cancel_clicked_cb), decrypt_widgets);

    gint result = gtk_dialog_run (GTK_DIALOG (decrypt_widgets->dialog));
    switch (result) {
        case GTK_RESPONSE_DELETE_EVENT:
            if (decrypt_widgets->dec_thread != NULL) {
                gpointer msg = g_thread_join (decrypt_widgets->dec_thread);
                if (msg != NULL) {
                    show_message_dialog (decrypt_widgets->main_window, (gchar *) msg, GTK_MESSAGE_ERROR);
                    g_free (msg);
                }
            }
            gtk_widget_destroy (decrypt_widgets->dialog);
            multiple_free (2, (gpointer) &decrypt_widgets->filename, (gpointer) &decrypt_widgets);
            break;
        default:
            break;
    }
}


static void
cancel_clicked_cb (GtkWidget *btn __attribute__((__unused__)),
                   gpointer user_data)
{
    DecryptWidgets *decrypt_widgets = user_data;

    gtk_widget_destroy (decrypt_widgets->dialog);

    multiple_free (2, (gpointer) &decrypt_widgets->filename, (gpointer) &decrypt_widgets);
}


static void
prepare_decryption_cb (GtkWidget *w __attribute__((__unused__)),
                    gpointer user_data)
{
    DecryptWidgets *data = user_data;
    ThreadData *thread_data = g_new0 (ThreadData, 1);

    thread_data->dialog = data->dialog;
    thread_data->spinner = data->spinner;
    thread_data->message_label = data->message_label;
    thread_data->filename = data->filename;
    thread_data->pwd = gtk_entry_get_text (GTK_ENTRY (data->entry_pwd));

    if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data->ck_btn_delete))) {
        thread_data->delete_file = TRUE;
    }
    else {
        thread_data->delete_file = FALSE;
    }

    gtk_widget_show (thread_data->spinner);
    start_spinner (thread_data->spinner);

    change_widgets_sensitivity (4, FALSE, &data->ok_btn, &data->cancel_btn, &data->entry_pwd, &data->ck_btn_delete);

    data->dec_thread = g_thread_new (NULL, exec_thread, thread_data);
}


static gpointer
exec_thread (gpointer user_data)
{
    ThreadData *data = user_data;

    gchar *basename = g_path_get_basename (data->filename);

    gchar *message = g_strconcat ("Decrypting <b>", basename, "</b>...", NULL);
    set_label_message (data->message_label, message);
    gpointer msg = decrypt_file (data->filename, data->pwd);

    if (data->delete_file) {
        message = g_strconcat ("Deleting <b>", basename, "</b>...", NULL);
        set_label_message (data->message_label, message);
        g_unlink (data->filename);
    }

    gtk_dialog_response (GTK_DIALOG (data->dialog), GTK_RESPONSE_DELETE_EVENT);

    multiple_free (3, (gpointer) &data, (gpointer) &basename, (gpointer) &message);

    g_thread_exit (msg);
}
