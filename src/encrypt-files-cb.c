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

static void     encrypt_dialog_response_cb  (GObject      *source,
                                             GAsyncResult *result,
                                             gpointer      user_data);

static void     encrypt_choose_files_cb     (GObject      *source,
                                             GAsyncResult *result,
                                             gpointer      user_data);

void
encrypt_files_cb (GtkWidget *btn __attribute__((__unused__)),
                  gpointer   user_data)
{
    EncryptWidgets *encrypt_widgets = g_new0 (EncryptWidgets, 1);

    encrypt_widgets->main_window = (GtkWidget *)user_data;
    encrypt_widgets->running_threads = 0;
    encrypt_widgets->files_not_encrypted = 0;
    encrypt_widgets->first_run = TRUE;

    choose_file_async (GTK_WINDOW (encrypt_widgets->main_window),
                       "Choose file(s) to encrypt",
                       TRUE,
                       NULL,
                       encrypt_choose_files_cb,
                       encrypt_widgets);
}

static void
encrypt_choose_files_cb (GObject      *source,
                         GAsyncResult *result,
                         gpointer      user_data)
{
    EncryptWidgets *encrypt_widgets = user_data;
    GtkBuilder *builder = get_builder_from_path (PARTIAL_PATH_TO_UI_FILE);
    GError *error = NULL;

    encrypt_widgets->files_list = choose_file_finish (GTK_WINDOW (source), result, &error);
    if (error != NULL) {
        g_error_free (error);
    }
    if (encrypt_widgets->files_list == NULL) {
        g_free (encrypt_widgets);
        return;
    }

    if (builder == NULL) {
        g_slist_free_full (encrypt_widgets->files_list, g_free);
        g_free (encrypt_widgets);
        return;
    }

    encrypt_widgets->dialog = GTK_WIDGET (gtk_builder_get_object (builder, "enc_pwd_diag"));
    g_object_ref (encrypt_widgets->dialog);
    encrypt_widgets->ok_btn = GTK_WIDGET (gtk_builder_get_object (builder, "ok_btn_pwd_diag"));
    encrypt_widgets->cancel_btn = GTK_WIDGET (gtk_builder_get_object (builder, "cancel_btn_pwd_diag"));
    encrypt_widgets->entry_pwd = GTK_WIDGET (gtk_builder_get_object (builder, "pwd_entry1"));
    encrypt_widgets->entry_pwd_retype = GTK_WIDGET (gtk_builder_get_object (builder, "pwd_entry2"));
    encrypt_widgets->message_label = GTK_WIDGET (gtk_builder_get_object (builder, "enc_label"));
    encrypt_widgets->spinner = GTK_WIDGET (gtk_builder_get_object (builder, "enc_spinner"));
    encrypt_widgets->header_bar_menu = GTK_WIDGET (gtk_builder_get_object (builder, "enc_menu_btn"));
    GtkWidget *header_bar = GTK_WIDGET (gtk_builder_get_object (builder, "hd_bar_enc"));
    GtkWidget *header_bar_title = gtk_label_new ("Encryption Password");
    encrypt_widgets->algo_buttons[0] = GTK_WIDGET (gtk_builder_get_object (builder, "aes_rbtn"));
    encrypt_widgets->algo_buttons[1] = GTK_WIDGET (gtk_builder_get_object (builder, "twofish_rbtn"));
    encrypt_widgets->algo_buttons[2] = GTK_WIDGET (gtk_builder_get_object (builder, "serpent_rbtn"));
    encrypt_widgets->algo_buttons[3] = GTK_WIDGET (gtk_builder_get_object (builder, "camellia_rbtn"));
    encrypt_widgets->mode_buttons[0] = GTK_WIDGET (gtk_builder_get_object (builder, "ctr_rbtn"));
    encrypt_widgets->mode_buttons[1] = GTK_WIDGET (gtk_builder_get_object (builder, "cbc_rbtn"));
    gtk_header_bar_set_title_widget (GTK_HEADER_BAR (header_bar), header_bar_title);
    gtk_menu_button_set_child (GTK_MENU_BUTTON (encrypt_widgets->header_bar_menu),
                               GTK_WIDGET (gtk_builder_get_object (builder, "menu_image")));
    g_object_unref (builder);

    gtk_widget_set_visible (encrypt_widgets->spinner, FALSE);

    g_signal_connect (encrypt_widgets->entry_pwd_retype, "activate", G_CALLBACK (entry_activated_cb), encrypt_widgets);
    g_signal_connect (encrypt_widgets->ok_btn, "clicked", G_CALLBACK (entry_activated_cb), encrypt_widgets);
    g_signal_connect (encrypt_widgets->cancel_btn, "clicked", G_CALLBACK (cancel_clicked_cb), encrypt_widgets);
    encrypt_widgets->source_id = g_timeout_add (500, check_tp, encrypt_widgets);

    dialog_run_async (GTK_WINDOW (encrypt_widgets->dialog), NULL, encrypt_dialog_response_cb, encrypt_widgets);
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
entry_activated_cb (GtkWidget *entry __attribute__((unused)),
                    gpointer   user_data)
{
    EncryptWidgets *encrypt_widgets = user_data;
    const gchar *algo = NULL, *mode = NULL;

    if (!check_pwd (encrypt_widgets->main_window, encrypt_widgets->entry_pwd, encrypt_widgets->entry_pwd_retype)) {
        return;
    } else {
        for (guint i = 0; i < G_N_ELEMENTS (encrypt_widgets->algo_buttons); i++) {
            if (gtk_check_button_get_active (GTK_CHECK_BUTTON (encrypt_widgets->algo_buttons[i]))) {
                algo = gtk_widget_get_name (encrypt_widgets->algo_buttons[i]);
                break;
            }
        }
        for (guint i = 0; i < G_N_ELEMENTS (encrypt_widgets->mode_buttons); i++) {
            if (gtk_check_button_get_active (GTK_CHECK_BUTTON (encrypt_widgets->mode_buttons[i]))) {
                mode = gtk_widget_get_name (encrypt_widgets->mode_buttons[i]);
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
    const gchar *text_entry = gtk_editable_get_text (GTK_EDITABLE (entry));
    const gchar *text_retype_entry = gtk_editable_get_text (GTK_EDITABLE (retype_entry));

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
    thread_data->pwd = gtk_editable_get_text (GTK_EDITABLE (data->entry_pwd));
    thread_data->widgets = data;

    gtk_label_set_label (GTK_LABEL (data->message_label), "Encrypting file(s)...");
    gtk_widget_set_visible (thread_data->spinner, TRUE);
    start_spinner (thread_data->spinner);

    change_widgets_sensitivity (4, FALSE, &data->ok_btn, &data->cancel_btn, &data->entry_pwd, &data->entry_pwd_retype);

    g_mutex_init (&thread_data->mutex);

    data->thread_pool = g_thread_pool_new (exec_thread, thread_data, g_get_num_processors (), TRUE, NULL);
    for (guint i = 0; i < thread_data->list_len; i++) {
        g_thread_pool_push (data->thread_pool, g_slist_nth_data (data->files_list, i), NULL);
    }

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

    dialog_set_response (GTK_WINDOW (encrypt_widgets->dialog), GTK_RESPONSE_CANCEL);
    gtk_window_destroy (GTK_WINDOW (encrypt_widgets->dialog));
}

static void
encrypt_dialog_response_cb (GObject      *source,
                            GAsyncResult *result,
                            gpointer      user_data)
{
    EncryptWidgets *encrypt_widgets = user_data;
    GtkWindow *dialog = GTK_WINDOW (source);
    GError *error = NULL;
    gint response = dialog_run_finish (dialog, result, &error);

    if (error != NULL) {
        g_error_free (error);
        response = GTK_RESPONSE_NONE;
    }

    if (encrypt_widgets->source_id != 0) {
        g_source_remove (encrypt_widgets->source_id);
        encrypt_widgets->source_id = 0;
    }

    if (response == GTK_RESPONSE_CANCEL || response == GTK_RESPONSE_DELETE_EVENT) {
        g_object_unref (encrypt_widgets->dialog);
        g_slist_free_full (encrypt_widgets->files_list, g_free);
        g_free (encrypt_widgets);
    }
}
