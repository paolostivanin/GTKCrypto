#include <gtk/gtk.h>
#include "gtkcrypto.h"
#include "common-widgets.h"

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
    GThread *enc_thread;
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

static void prepare_decryption (GtkWidget *, gpointer user_data);


void
decrypt_file_cb (GtkWidget *btn __attribute__((__unused__)),
                 gpointer user_data) {
    DecryptWidgets *decrypt_widgets = g_new0 (DecryptWidgets, 1);

    decrypt_widgets->main_window = user_data;

    decrypt_widgets->filename = choose_file(decrypt_widgets->main_window);

    decrypt_widgets->dialog = create_dialog(decrypt_widgets->main_window, "enc_dialog", NULL);
    decrypt_widgets->cancel_btn = gtk_button_new_with_label("Cancel");
    decrypt_widgets->ok_btn = gtk_button_new_with_label("OK");
    gtk_widget_set_size_request(decrypt_widgets->dialog, 600, -1);

    // TODO complete me

    g_signal_connect (decrypt_widgets->entry_pwd, "activate", G_CALLBACK (prepare_decryption), decrypt_widgets);
    g_signal_connect (decrypt_widgets->ok_btn, "clicked", G_CALLBACK (prepare_decryption), decrypt_widgets);
    g_signal_connect (decrypt_widgets->cancel_btn, "clicked", G_CALLBACK(cancel_clicked_cb), decrypt_widgets);

    gint result = gtk_dialog_run (GTK_DIALOG (decrypt_widgets->dialog));
    switch (result) {
        case GTK_RESPONSE_DELETE_EVENT:
            g_thread_join (decrypt_widgets->enc_thread);
            gtk_widget_destroy (decrypt_widgets->dialog);
            multiple_free (2, (gpointer *) &decrypt_widgets->filename, (gpointer *) &decrypt_widgets);
            break;
        default:
            break;
    }
}


static void
prepare_decryption (GtkWidget *w __attribute__((__unused__)),
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

    change_widgets_sensitivity (5, FALSE, &data->ok_btn, &data->cancel_btn, &data->entry_pwd, &data->ck_btn_delete);

    data->enc_thread = g_thread_new (NULL, exec_thread, thread_data);
}


static void
cancel_clicked_cb (GtkWidget *btn __attribute__((__unused__)),
                   gpointer user_data)
{
    DecryptWidgets *decrypt_widgets = user_data;

    gtk_widget_destroy (decrypt_widgets->dialog);

    multiple_free (2, (gpointer *) &decrypt_widgets->filename, (gpointer *) &decrypt_widgets);
}