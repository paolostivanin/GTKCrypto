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
    GPtrArray *key_fprs;
    const gchar *selected_fpr;
    GThread *sign_thread;
} SignFileWidgets;

typedef struct sign_thread_data_t {
    GtkWidget *dialog;
    GtkWidget *spinner;
    GtkWidget *message_label;
    const gchar *filename;
    const gchar *key_fingerprint;
} ThreadData;


static void     prepare_signing_cb  (GtkWidget *btn,
                                     gpointer   user_data);

static gpointer exec_thread         (gpointer   user_data);

static void     cancel_clicked_cb   (GtkWidget *btn,
                                     gpointer   user_data);


void
sign_file_cb (GtkWidget *btn __attribute__((unused)),
              gpointer   user_data)
{
    SignFileWidgets *sign_file_widgets = g_new0 (SignFileWidgets, 1);
    sign_file_widgets->sign_thread = NULL;

    sign_file_widgets->main_window = user_data;
    // TODO multiple files sign
    GSList *list = choose_file (sign_file_widgets->main_window, "Choose File", FALSE);
    sign_file_widgets->filename = get_filename_from_list (list);
    if (sign_file_widgets->filename == NULL) {
        g_free (sign_file_widgets);
        return;
    }
    sign_file_widgets->dialog = create_dialog (sign_file_widgets->main_window, "sign_fl_diag", "Select GPG key");
    sign_file_widgets->cancel_btn = gtk_button_new_with_label ("Cancel");
    sign_file_widgets->ok_btn = gtk_button_new_with_label ("OK");
    gtk_widget_set_size_request (sign_file_widgets->dialog, 800, -1);

    sign_file_widgets->message_label = gtk_label_new ("");

    sign_file_widgets->spinner = create_spinner ();

    sign_file_widgets->gpg_keys = get_available_keys ();

    if (sign_file_widgets->gpg_keys == NULL) {
        show_message_dialog (sign_file_widgets->main_window, "No GPG keys available", GTK_MESSAGE_INFO);
        g_free (sign_file_widgets);
        return;
    }

    GtkStringList *key_list = gtk_string_list_new (NULL);
    sign_file_widgets->combo_box = gtk_drop_down_new (G_LIST_MODEL (key_list), NULL);
    sign_file_widgets->key_fprs = g_ptr_array_new_with_free_func (g_free);
    sign_file_widgets->selected_fpr = NULL;

    gtk_widget_set_hexpand (sign_file_widgets->combo_box, TRUE);
    gtk_widget_set_hexpand (sign_file_widgets->message_label, TRUE);

    gchar *str;
    sign_file_widgets->to_free = NULL;

    for (guint i = 0; i < g_slist_length (sign_file_widgets->gpg_keys); i++) {
        KeyInfo *key_data = g_slist_nth_data (sign_file_widgets->gpg_keys, i);
        if (g_utf8_strlen (key_data->name, -1) + g_utf8_strlen (key_data->email, -1) > 128) {
            str = g_strconcat ("Name and email too long. Key ID: ", key_data->key_id, NULL);
        } else {
            str = g_strconcat (key_data->name, " <", key_data->email, "> (", key_data->key_id, ")", NULL);
        }
        sign_file_widgets->to_free = g_slist_append (sign_file_widgets->to_free, g_strdup (str));
        g_free (str);
        gtk_string_list_append (key_list, (gchar *) g_slist_nth_data (sign_file_widgets->to_free, i));
        g_ptr_array_add (sign_file_widgets->key_fprs, g_strdup (key_data->key_fpr));
    }
    if (sign_file_widgets->key_fprs->len > 0) {
        gtk_drop_down_set_selected (GTK_DROP_DOWN (sign_file_widgets->combo_box), 0);
    }
    g_object_unref (key_list);

    GtkWidget *grid = gtk_grid_new ();
    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_attach (GTK_GRID (grid), sign_file_widgets->combo_box, 0, 0, 4, 1);
    gtk_grid_attach (GTK_GRID (grid), sign_file_widgets->message_label, 0, 1, 2, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), sign_file_widgets->spinner, sign_file_widgets->message_label, GTK_POS_RIGHT, 1, 1);

    GtkWidget *hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_append (GTK_BOX(hbox), sign_file_widgets->ok_btn);
    gtk_box_append (GTK_BOX(hbox), sign_file_widgets->cancel_btn);
    gtk_grid_attach (GTK_GRID (grid), hbox, 3, 4, 1, 1);

    gtk_box_append (GTK_BOX (get_dialog_content_area (sign_file_widgets->dialog)), grid);

    gtk_widget_set_visible (sign_file_widgets->spinner, FALSE);

    g_signal_connect (sign_file_widgets->ok_btn, "clicked", G_CALLBACK (prepare_signing_cb), sign_file_widgets);
    g_signal_connect (sign_file_widgets->combo_box, "notify::selected", G_CALLBACK (prepare_signing_cb), sign_file_widgets);
    g_signal_connect (sign_file_widgets->cancel_btn, "clicked", G_CALLBACK (cancel_clicked_cb), sign_file_widgets);

    gint result = run_dialog (GTK_WINDOW (sign_file_widgets->dialog));
    switch (result) {
        case GTK_RESPONSE_DELETE_EVENT:
            if (sign_file_widgets->sign_thread != NULL) {
                gpointer status = g_thread_join (sign_file_widgets->sign_thread);
                if (status != SIGN_OK) {
                    show_message_dialog (sign_file_widgets->main_window, "Couldn't sign file", GTK_MESSAGE_ERROR);
                }
                else {
                    gchar *info_message = g_strconcat ("File <b>", sign_file_widgets->filename, "</b> has been successfully signed\n"
                            "(GPG key fingerprint: ", sign_file_widgets->selected_fpr, ")", NULL);
                    show_message_dialog (sign_file_widgets->dialog, info_message, GTK_MESSAGE_INFO);
                    g_free (info_message);
                }
            }
            g_slist_free_full (sign_file_widgets->gpg_keys, g_free);
            g_slist_free_full (sign_file_widgets->to_free, g_free);
            g_ptr_array_unref (sign_file_widgets->key_fprs);
            gtk_window_destroy (GTK_WINDOW (sign_file_widgets->dialog));
            g_free (sign_file_widgets->filename);
            g_free (sign_file_widgets);
            break;
        default:
            break;
    }
}


static void
cancel_clicked_cb (GtkWidget *btn __attribute__((unused)),
                   gpointer   user_data)
{
    SignFileWidgets *data = user_data;

    g_slist_free_full (data->gpg_keys, g_free);
    g_slist_free_full (data->to_free, g_free);
    g_ptr_array_unref (data->key_fprs);

    dialog_set_response (GTK_WINDOW (data->dialog), GTK_RESPONSE_CANCEL);
    gtk_window_destroy (GTK_WINDOW (data->dialog));

    g_free (data->filename);
    g_free (data);
}


static void
prepare_signing_cb (GtkWidget *btn __attribute__((unused)),
                    gpointer   user_data)
{
    SignFileWidgets *data = user_data;
    ThreadData *thread_data = g_new0 (ThreadData, 1);

    thread_data->dialog = data->dialog;
    thread_data->spinner = data->spinner;
    thread_data->message_label = data->message_label;
    thread_data->filename = data->filename;
    guint selected = gtk_drop_down_get_selected (GTK_DROP_DOWN (data->combo_box));
    if (selected >= data->key_fprs->len) {
        show_message_dialog (data->dialog, "No GPG key selected", GTK_MESSAGE_ERROR);
        dialog_finish_response (GTK_WINDOW (data->dialog), GTK_RESPONSE_DELETE_EVENT);
        g_free (thread_data);
        return;
    }
    data->selected_fpr = g_ptr_array_index (data->key_fprs, selected);
    thread_data->key_fingerprint = data->selected_fpr;

    gtk_widget_set_visible (thread_data->spinner, TRUE);
    start_spinner (thread_data->spinner);

    change_widgets_sensitivity (3, FALSE, &data->ok_btn, &data->cancel_btn, &data->combo_box);

    data->sign_thread = g_thread_new (NULL, exec_thread, thread_data);
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
static gpointer
exec_thread (gpointer user_data)
{
    ThreadData *data = user_data;

    gchar *basename = g_path_get_basename (data->filename);

    gchar *message = g_strconcat ("Signing <b>", basename, "</b>...", NULL);
    set_label_message (data->message_label, message);
    gpointer status = sign_file (data->filename, data->key_fingerprint);

    dialog_finish_response (GTK_WINDOW (data->dialog), GTK_RESPONSE_DELETE_EVENT);

    g_free (data);
    g_free (basename);
    g_free (message);

    g_thread_exit (status);
} //-V591
#pragma GCC diagnostic pop
