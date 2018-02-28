#include <gtk/gtk.h>
#include "gtkcrypto.h"
#include "encrypt-files-cb.h"
#include "common-callbacks.h"

static gboolean check_tp                    (gpointer data);

static void     entry_activated_cb          (GtkWidget *entry,
                                             gpointer   user_data);

static gboolean check_pwd                   (GtkWidget *main_window,
                                             GtkWidget *entry,
                                             GtkWidget *retype_entry);

static void     prepare_multi_encryption    (const gchar    *algo,
                                             const gchar    *algo_mode,
                                             EncryptWidgets *data);

static void     exec_thread                 (gpointer data,
                                             gpointer user_data);

static void     cancel_clicked_cb           (GtkWidget *btn,
                                             gpointer   user_data);


void
encrypt_files_cb (GtkWidget *btn __attribute__((__unused__)),
                  gpointer   user_data)
{
    EncryptWidgets *encrypt_widgets = g_new0 (EncryptWidgets, 1);

    encrypt_widgets->main_window = (GtkWidget *)user_data;
    encrypt_widgets->running_threads = 0;
    encrypt_widgets->files_not_encrypted = 0;
    encrypt_widgets->first_run = TRUE;

    encrypt_widgets->files_list = choose_file (encrypt_widgets->main_window, "Choose file(s) to encrypt", TRUE);
    if (encrypt_widgets->files_list == NULL) {
        g_free (encrypt_widgets);
        return;
    }

    GtkBuilder *builder = gtk_builder_new_from_file (PATH_TO_UI_FILE);
    encrypt_widgets->dialog = GTK_WIDGET (gtk_builder_get_object (builder, "enc_pwd_diag"));
    encrypt_widgets->ok_btn = GTK_WIDGET (gtk_builder_get_object (builder, "ok_btn_pwd_diag"));
    encrypt_widgets->cancel_btn = GTK_WIDGET (gtk_builder_get_object (builder, "cancel_btn_pwd_diag"));
    encrypt_widgets->entry_pwd = GTK_WIDGET (gtk_builder_get_object (builder, "pwd_entry1"));
    encrypt_widgets->entry_pwd_retype = GTK_WIDGET (gtk_builder_get_object (builder, "pwd_entry2"));
    encrypt_widgets->message_label = GTK_WIDGET (gtk_builder_get_object (builder, "enc_label"));
    encrypt_widgets->spinner = GTK_WIDGET (gtk_builder_get_object (builder, "enc_spinner"));
    encrypt_widgets->header_bar_menu = GTK_WIDGET (gtk_builder_get_object (builder, "enc_menu_btn"));
    GtkWidget *popover_menu = GTK_WIDGET (gtk_builder_get_object (builder, "enc_popmenu"));
    encrypt_widgets->radio_btns_algo_list = gtk_radio_button_get_group (GTK_RADIO_BUTTON (gtk_builder_get_object (builder, "aes_rbtn")));
    encrypt_widgets->radio_btns_mode_list = gtk_radio_button_get_group (GTK_RADIO_BUTTON (gtk_builder_get_object (builder, "ctr_rbtn")));
    gtk_container_add (GTK_CONTAINER (encrypt_widgets->header_bar_menu), GTK_WIDGET (gtk_builder_get_object (builder, "menu_image")));
    g_object_unref (builder);

    gtk_widget_show_all (encrypt_widgets->dialog);
    gtk_widget_hide (encrypt_widgets->spinner);

    g_signal_connect (encrypt_widgets->entry_pwd_retype, "activate", G_CALLBACK (entry_activated_cb), encrypt_widgets);
    g_signal_connect (encrypt_widgets->ok_btn, "clicked", G_CALLBACK (entry_activated_cb), encrypt_widgets);
    g_signal_connect (encrypt_widgets->cancel_btn, "clicked", G_CALLBACK (cancel_clicked_cb), encrypt_widgets);
    g_signal_connect (encrypt_widgets->header_bar_menu, "toggled", G_CALLBACK (toggle_changed_cb), popover_menu);
    g_signal_connect_swapped (encrypt_widgets->dialog, "button-press-event", G_CALLBACK (toggle_active_cb), encrypt_widgets->header_bar_menu);

    encrypt_widgets->source_id = g_timeout_add (500, check_tp, encrypt_widgets);

    gtk_dialog_run (GTK_DIALOG (encrypt_widgets->dialog));
}


static gboolean
check_tp (gpointer data)
{
    EncryptWidgets *widgets = (EncryptWidgets *)data;
    if (widgets->running_threads == 0 && widgets->first_run == FALSE) {
        g_thread_pool_free (widgets->thread_pool, FALSE, TRUE);
        guint list_len = g_slist_length (widgets->files_list);
        // TODO show failed files
        gchar *msg = g_strdup_printf ("%u/%u file(s) successfully encrypted.", list_len - widgets->files_not_encrypted, list_len);
        show_message_dialog (widgets->main_window, msg, GTK_MESSAGE_INFO);
        g_free (msg);
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
    const gchar *algo = NULL, *mode = NULL;

    if (!check_pwd (encrypt_widgets->main_window, encrypt_widgets->entry_pwd, encrypt_widgets->entry_pwd_retype)) {
        return;
    } else {
        for (guint i = 0; i < g_slist_length (encrypt_widgets->radio_btns_algo_list); i++) {
            if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (g_slist_nth_data (encrypt_widgets->radio_btns_algo_list, i)))) {
                algo = gtk_widget_get_name (g_slist_nth_data (encrypt_widgets->radio_btns_algo_list, i));
                break;
            }
        }
        for (guint i = 0; i < g_slist_length (encrypt_widgets->radio_btns_mode_list); i++) {
            if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (g_slist_nth_data (encrypt_widgets->radio_btns_mode_list, i)))) {
                mode = gtk_widget_get_name (g_slist_nth_data (encrypt_widgets->radio_btns_mode_list, i));
                break;
            }
        }
        prepare_multi_encryption (algo, mode, encrypt_widgets);
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

    gpointer ret = encrypt_file (filename, thread_data->pwd, thread_data->algo_btn_name, thread_data->algo_mode_btn_name);
    if (ret != NULL) {
        g_mutex_lock (&thread_data->mutex);
        thread_data->widgets->files_not_encrypted++;
        g_mutex_unlock (&thread_data->mutex);
        // TODO deal with error
    }

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

    g_source_remove (encrypt_widgets->source_id);

    gtk_widget_destroy (encrypt_widgets->dialog);

    g_slist_free_full (encrypt_widgets->files_list, g_free);

    g_free (encrypt_widgets);
}