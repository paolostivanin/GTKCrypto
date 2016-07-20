#include <gtk/gtk.h>
#include "common-widgets.h"
#include "gtkcrypto.h"
#include "gpgme-misc.h"


typedef struct sign_file_widgets_t {
    GtkWidget *main_window;
    GtkWidget *dialog;
    GtkWidget *combo_box;
    GtkWidget *cancel_btn;
    GtkWidget *ok_btn;
    GtkWidget *spinner;
    GtkWidget *message_label;
    gchar *filename;
    GSList *gpg_keys;
    GSList *to_free;
    GThread *sign_thread;
} SignFileWidgets;

typedef struct sign_thread_data_t {
    GtkWidget *dialog;
    GtkWidget *spinner;
    GtkWidget *message_label;
    const gchar *filename;
    const gchar *key_fingerprint;
} ThreadData;

static void cancel_clicked_cb (GtkWidget *button, gpointer user_data);

static void prepare_signing_cb (GtkWidget *button, gpointer user_data);

static gpointer exec_thread (gpointer user_data);


void
sign_file_cb (GtkWidget *btn __attribute__((__unused__)),
              gpointer user_data)
{
    SignFileWidgets *sign_file_widgets = g_new0 (SignFileWidgets, 1);
    sign_file_widgets->sign_thread = NULL;

    sign_file_widgets->main_window = user_data;
    sign_file_widgets->filename = choose_file (sign_file_widgets->main_window);

    sign_file_widgets->dialog = create_dialog (sign_file_widgets->main_window, "sign_fl_diag", "Select GPG key");
    sign_file_widgets->cancel_btn = gtk_button_new_with_label ("Cancel");
    sign_file_widgets->ok_btn = gtk_button_new_with_label ("OK");
    gtk_widget_set_size_request (sign_file_widgets->dialog, 800, -1);

    sign_file_widgets->message_label = gtk_label_new ("");

    sign_file_widgets->spinner = create_spinner ();

    sign_file_widgets->gpg_keys = get_available_keys ();

    sign_file_widgets->combo_box = gtk_combo_box_text_new ();

    gtk_widget_set_hexpand (sign_file_widgets->combo_box, TRUE);
    gtk_widget_set_hexpand (sign_file_widgets->message_label, TRUE);

    gint i;
    gchar *str;
    sign_file_widgets->to_free = NULL;

    for (i = 0; i < g_slist_length (sign_file_widgets->gpg_keys); i++) {
        if (g_utf8_strlen (((KeyInfo *) (sign_file_widgets->gpg_keys->data))->name, -1) +
            g_utf8_strlen (((KeyInfo *) (sign_file_widgets->gpg_keys->data))->email, -1) > 128) {
                str = g_strconcat ("Name and email too long. Key ID: ", ((KeyInfo *) (sign_file_widgets->gpg_keys->data))->key_id, NULL);
        }
        else {
            str = g_strconcat (((KeyInfo *) (sign_file_widgets->gpg_keys->data))->name, " <", ((KeyInfo *) (sign_file_widgets->gpg_keys->data))->email, "> (",
                              ((KeyInfo *) (sign_file_widgets->gpg_keys->data))->key_id, ")", NULL);
        }
        sign_file_widgets->to_free = g_slist_append (sign_file_widgets->to_free, g_strdup (str));
        g_free (str);
        gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (sign_file_widgets->combo_box), ((KeyInfo *) (sign_file_widgets->gpg_keys->data))->key_fpr,
                                        (gchar *) g_slist_nth_data (sign_file_widgets->to_free, g_slist_length (sign_file_widgets->to_free) - 1));
    }

    GtkWidget *grid = gtk_grid_new ();
    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_attach (GTK_GRID (grid), sign_file_widgets->combo_box, 0, 0, 4, 1);
    gtk_grid_attach (GTK_GRID (grid), sign_file_widgets->message_label, 0, 1, 2, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), sign_file_widgets->spinner, sign_file_widgets->message_label, GTK_POS_RIGHT, 1, 1);

    GtkWidget *hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_end (GTK_BOX(hbox), sign_file_widgets->ok_btn, TRUE, TRUE, 0);
    gtk_box_pack_end (GTK_BOX(hbox), sign_file_widgets->cancel_btn, TRUE, TRUE, 0);
    gtk_grid_attach (GTK_GRID (grid), hbox, 3, 4, 1, 1);

    gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (GTK_DIALOG (sign_file_widgets->dialog))), grid);

    gtk_widget_show_all (sign_file_widgets->dialog);

    gtk_widget_hide (sign_file_widgets->spinner);

    g_signal_connect (sign_file_widgets->ok_btn, "clicked", G_CALLBACK (prepare_signing_cb), sign_file_widgets);
    g_signal_connect (sign_file_widgets->combo_box, "changed", G_CALLBACK (prepare_signing_cb), sign_file_widgets);
    g_signal_connect (sign_file_widgets->cancel_btn, "clicked", G_CALLBACK (cancel_clicked_cb), sign_file_widgets);

    gint result = gtk_dialog_run (GTK_DIALOG (sign_file_widgets->dialog));
    switch (result) {
        case GTK_RESPONSE_DELETE_EVENT:
            if (sign_file_widgets->sign_thread != NULL) {
                g_thread_join (sign_file_widgets->sign_thread);
            }

            gchar *info_message = g_strconcat ("File <b>", sign_file_widgets->filename, "</b> has been successfully signed\n"
                    "(GPG key fingerprint: ", gtk_combo_box_get_active_id (GTK_COMBO_BOX (sign_file_widgets->combo_box)), ")", NULL);
            show_message_dialog (sign_file_widgets->dialog, info_message, GTK_MESSAGE_INFO);
            g_free (info_message);

            g_slist_free_full (sign_file_widgets->gpg_keys, g_free);
            g_slist_free_full (sign_file_widgets->to_free, g_free);

            gtk_widget_destroy (sign_file_widgets->dialog);

            multiple_free (2, (gpointer) &sign_file_widgets->filename, (gpointer) &sign_file_widgets);
            break;
        default:
            break;
    }

    return;
}


static void
cancel_clicked_cb (GtkWidget *btn __attribute__((__unused__)),
                   gpointer user_data)
{
    SignFileWidgets *data = user_data;

    g_slist_free_full (data->gpg_keys, g_free);
    g_slist_free_full (data->to_free, g_free);

    gtk_widget_destroy (data->dialog);

    multiple_free (2, (gpointer) &data->filename, (gpointer) &data);
}


static void
prepare_signing_cb (GtkWidget *w __attribute__((__unused__)),
                       gpointer user_data)
{
    SignFileWidgets *data = user_data;
    ThreadData *thread_data = g_new0 (ThreadData, 1);

    thread_data->dialog = data->dialog;
    thread_data->spinner = data->spinner;
    thread_data->message_label = data->message_label;
    thread_data->filename = data->filename;
    thread_data->key_fingerprint = gtk_combo_box_get_active_id (GTK_COMBO_BOX (data->combo_box));

    gtk_widget_show (thread_data->spinner);
    start_spinner (thread_data->spinner);

    change_widgets_sensitivity (3, FALSE, &data->ok_btn, &data->cancel_btn, &data->combo_box);

    data->sign_thread = g_thread_new (NULL, exec_thread, thread_data);
}


static gpointer
exec_thread (gpointer user_data)
{
    ThreadData *data = user_data;

    gchar *basename = g_path_get_basename (data->filename);

    gchar *message = g_strconcat ("Signing <b>", basename, "</b>...", NULL);
    set_label_message (data->message_label, message);
    sign_file (data->filename, data->key_fingerprint);

    gtk_dialog_response (GTK_DIALOG (data->dialog), GTK_RESPONSE_DELETE_EVENT);

    multiple_free (3, (gpointer) &data, (gpointer) &basename, (gpointer) &message);

    g_thread_exit ((gpointer) 0);
}
