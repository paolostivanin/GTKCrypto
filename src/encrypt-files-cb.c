#include <gtk/gtk.h>
#include "gtkcrypto.h"
#include "encrypt-cb-ui.h"

static gboolean check_tp (gpointer data);

static void entry_activated_cb (GtkWidget *entry, gpointer user_data);

static gboolean check_pwd (GtkWidget *main_window, GtkWidget *entry, GtkWidget *retype_entry);

static void prepare_multi_encryption (const gchar *algo, const gchar *algo_mode, EncryptWidgets *);

static void exec_thread (gpointer data, gpointer user_data);

static void cancel_clicked_cb (GtkWidget *, gpointer);


void
encrypt_files_cb (GtkWidget *btn __attribute__((__unused__)),
                  gpointer   user_data)
{
    EncryptWidgets *encrypt_widgets = g_new0 (EncryptWidgets, 1);

    encrypt_widgets->main_window = (GtkWidget *)user_data;
    encrypt_widgets->running_threads = 0;
    encrypt_widgets->first_run = TRUE;

    encrypt_widgets->files_list = choose_file (encrypt_widgets->main_window, "Choose file(s) to encrypt", TRUE);
    if (encrypt_widgets->files_list == NULL) {
        g_free (encrypt_widgets);
        return;
    }

    do_dialog (encrypt_widgets);

    encrypt_widgets->message_label = gtk_label_new ("");
    encrypt_widgets->spinner = create_spinner ();

    GtkWidget *grid = gtk_grid_new ();
    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_attach (GTK_GRID (grid), encrypt_widgets->entry_pwd, 0, 0, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), encrypt_widgets->entry_pwd_retype, 0, 1, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), encrypt_widgets->message_label, 0, 2, 2, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), encrypt_widgets->spinner, encrypt_widgets->message_label, GTK_POS_RIGHT, 1, 1);

    GtkWidget *hbox = create_hbox (encrypt_widgets);
    gtk_grid_attach (GTK_GRID (grid), hbox, 1, 3, 1, 1);

    gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (GTK_DIALOG (encrypt_widgets->dialog))), grid);

    gtk_widget_show_all (encrypt_widgets->dialog);

    gtk_widget_hide (encrypt_widgets->spinner);

    g_signal_connect (encrypt_widgets->entry_pwd_retype, "activate", G_CALLBACK (entry_activated_cb), encrypt_widgets);
    g_signal_connect (encrypt_widgets->ok_btn, "clicked", G_CALLBACK (entry_activated_cb), encrypt_widgets);
    g_signal_connect (encrypt_widgets->cancel_btn, "clicked", G_CALLBACK (cancel_clicked_cb), encrypt_widgets);

    g_timeout_add (500, check_tp, encrypt_widgets);

    gtk_dialog_run (GTK_DIALOG (encrypt_widgets->dialog));
}


static gboolean
check_tp (gpointer data)
{
    EncryptWidgets *widgets = (EncryptWidgets *)data;
    if (widgets->running_threads == 0 && widgets->first_run == FALSE) {
        g_thread_pool_free (widgets->thread_pool, FALSE, TRUE);
        show_message_dialog (widgets->main_window, "File(s) successfully encrypted.", GTK_MESSAGE_INFO);
        cancel_clicked_cb (NULL, widgets);
        return FALSE;
    } else {
        return TRUE;
    }
}


static void
entry_activated_cb (GtkWidget *entry __attribute__((__unused__)),
                    gpointer   user_data)
{
    EncryptWidgets *encrypt_widgets = user_data;
    gint i, j;

    if (!check_pwd (encrypt_widgets->main_window, encrypt_widgets->entry_pwd, encrypt_widgets->entry_pwd_retype)) {
        return;
    } else {
        for (i = 0; i < AVAILABLE_ALGO; i++) {
            if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (encrypt_widgets->radio_button_algo[i]))) {
                break;
            }
        }
        for (j = 0; j < AVAILABLE_ALGO_MODE; j++) {
            if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (encrypt_widgets->radio_button_algo_mode[j]))) {
                break;
            }
        }
        prepare_multi_encryption (gtk_widget_get_name(encrypt_widgets->radio_button_algo[i]),
                                  gtk_widget_get_name(encrypt_widgets->radio_button_algo_mode[j]),
                                  encrypt_widgets);

    }
}


static gboolean
check_pwd (GtkWidget *main_window,
           GtkWidget *entry,
           GtkWidget *retype_entry)
{
    const gchar *text_entry = gtk_entry_get_text (GTK_ENTRY (entry));
    const gchar *text_retype_entry = gtk_entry_get_text (GTK_ENTRY (retype_entry));

    gint cmp_retval = g_strcmp0 (text_entry, text_retype_entry);

    if (cmp_retval != 0) {
        show_message_dialog (main_window, "Passwords are different, try again...", GTK_MESSAGE_ERROR);
        return FALSE;
    } else if (g_utf8_strlen (text_entry, -1) < 8) {
        show_message_dialog (main_window, "Password is too short (less than 8 chars). Please choose a stronger password.", GTK_MESSAGE_ERROR);
        return FALSE;
    } else {
        return TRUE;
    }
}


static void
prepare_multi_encryption (const gchar    *algo,
                          const gchar    *algo_mode,
                          EncryptWidgets *data)
{
    ThreadData *thread_data = g_new0 (ThreadData, 1);

    thread_data->dialog = data->dialog;
    thread_data->spinner = data->spinner;
    thread_data->list_len = g_slist_length (data->files_list);
    thread_data->algo_btn_name = algo;
    thread_data->algo_mode_btn_name = algo_mode;
    thread_data->pwd = gtk_entry_get_text (GTK_ENTRY (data->entry_pwd));
    thread_data->widgets = data;

    gtk_label_set_label (GTK_LABEL (data->message_label), "Encrypting file(s)...");
    gtk_widget_show (thread_data->spinner);
    start_spinner (thread_data->spinner);

    change_widgets_sensitivity (4, FALSE, &data->ok_btn, &data->cancel_btn, &data->entry_pwd, &data->entry_pwd_retype);

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
    encrypt_file (filename, thread_data->pwd, thread_data->algo_btn_name, thread_data->algo_mode_btn_name);

    g_mutex_lock (&thread_data->mutex);
    thread_data->widgets->running_threads--;
    thread_data->widgets->first_run = FALSE;
    g_mutex_unlock (&thread_data->mutex);
}


static void
cancel_clicked_cb (GtkWidget *btn __attribute__((__unused__)),
                   gpointer   user_data)
{
    EncryptWidgets *encrypt_widgets = user_data;

    gtk_widget_destroy (encrypt_widgets->dialog);

    g_slist_free_full (encrypt_widgets->files_list, g_free);

    g_free (encrypt_widgets);
}