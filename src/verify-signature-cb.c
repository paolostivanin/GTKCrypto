#include <gtk/gtk.h>
#include "common-widgets.h"
#include "gtkcrypto.h"
#include "gpgme-misc.h"

#define MAX_SIG_FILE_SIZE 4096

typedef struct verify_signature_widgets_t {
    GtkWidget *main_window;
    GtkWidget *dialog;
    GtkWidget *cancel_btn;
    GtkWidget *signed_file_entry;
    GtkWidget *signature_file_entry;
    GtkWidget *spinner;
    GtkWidget *message_label;
    GThread *thread;
    struct {
        gchar *entry1_filename;
        gchar *entry2_filename;
        gboolean entry1_changed;
        gboolean entry2_changed;
    } entry_data;
} VerifyWidgets;

typedef struct verify_signature_thread_data_t {
    GtkWidget *dialog;
    GtkWidget *spinner;
    GtkWidget *message_label;
    gchar *signed_file;
    gchar *signature_file;
} ThreadData;

static void     select_file_cb          (GtkEntry               *entry,
                                         GtkEntryIconPosition    icon_pos,
                                         GdkEvent               *event,
                                         gpointer                user_data);

static void     cancel_btn_clicked_cb   (GtkWidget *btn,
                                         gpointer   user_data);

static void     entry_changed_cb        (GtkWidget *btn,
                                         gpointer   user_data);

static gpointer exec_thread             (gpointer user_data);


void
verify_signature_cb (GtkWidget *btn __attribute__((unused)),
                     gpointer   user_data)
{
    VerifyWidgets *verify_widgets = g_new0 (VerifyWidgets, 1);

    verify_widgets->thread = NULL;
    verify_widgets->entry_data.entry1_changed = FALSE;
    verify_widgets->entry_data.entry2_changed = FALSE;
    verify_widgets->main_window = user_data;

    verify_widgets->dialog = create_dialog (verify_widgets->main_window, "ver_sig_dialog", "Verify Signature");

    verify_widgets->cancel_btn = gtk_dialog_add_button (GTK_DIALOG (verify_widgets->dialog), "Cancel",
                                                        GTK_RESPONSE_CANCEL);
    gtk_widget_set_margin_top (verify_widgets->cancel_btn, 10);

    gtk_widget_set_size_request (verify_widgets->dialog, 600, -1);

    verify_widgets->signed_file_entry = gtk_entry_new ();
    gtk_widget_set_name (GTK_WIDGET (verify_widgets->signed_file_entry), "signed_file_entry");
    gtk_entry_set_placeholder_text (GTK_ENTRY (verify_widgets->signed_file_entry), "Choose signed file");
    gtk_editable_set_editable (GTK_EDITABLE (verify_widgets->signed_file_entry), FALSE);
    gtk_widget_set_hexpand (verify_widgets->signed_file_entry, TRUE);
    gtk_entry_set_icon_from_icon_name (GTK_ENTRY (verify_widgets->signed_file_entry), GTK_ENTRY_ICON_SECONDARY,
                                       "document-open-symbolic");

    verify_widgets->signature_file_entry = gtk_entry_new ();
    gtk_widget_set_name (GTK_WIDGET (verify_widgets->signature_file_entry), "signature_file_entry");
    gtk_entry_set_placeholder_text (GTK_ENTRY (verify_widgets->signature_file_entry), "Choose signature (.sig) file");
    gtk_editable_set_editable (GTK_EDITABLE (verify_widgets->signature_file_entry), FALSE);
    gtk_widget_set_hexpand (verify_widgets->signature_file_entry, TRUE);
    gtk_entry_set_icon_from_icon_name (GTK_ENTRY (verify_widgets->signature_file_entry), GTK_ENTRY_ICON_SECONDARY,
                                       "document-open-symbolic");

    verify_widgets->message_label = gtk_label_new ("");

    verify_widgets->spinner = create_spinner ();

    GtkWidget *grid = gtk_grid_new ();
    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_attach (GTK_GRID (grid), verify_widgets->signed_file_entry, 0, 0, 4, 1);
    gtk_grid_attach (GTK_GRID (grid), verify_widgets->signature_file_entry, 0, 1, 4, 1);
    gtk_grid_attach (GTK_GRID (grid), verify_widgets->message_label, 0, 2, 3, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), verify_widgets->spinner, verify_widgets->message_label,
                             GTK_POS_RIGHT, 1, 1);

    gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (GTK_DIALOG (verify_widgets->dialog))), grid);

    g_signal_connect (verify_widgets->signed_file_entry, "icon-press", G_CALLBACK (select_file_cb), verify_widgets);
    g_signal_connect (verify_widgets->signature_file_entry, "icon-press", G_CALLBACK (select_file_cb), verify_widgets);
    g_signal_connect (verify_widgets->cancel_btn, "clicked", G_CALLBACK (cancel_btn_clicked_cb), verify_widgets);
    g_signal_connect (verify_widgets->signed_file_entry, "changed", G_CALLBACK (entry_changed_cb), verify_widgets);
    g_signal_connect (verify_widgets->signature_file_entry, "changed", G_CALLBACK (entry_changed_cb), verify_widgets);

    gtk_widget_show_all (verify_widgets->dialog);

    gint result = gtk_dialog_run (GTK_DIALOG (verify_widgets->dialog));
    switch (result) {
        case GTK_RESPONSE_DELETE_EVENT:
            if (verify_widgets->thread != NULL) {
                gpointer status = g_thread_join (verify_widgets->thread);
                if (status == BAD_SIGNATURE) {
                    show_message_dialog (verify_widgets->main_window, "Bad signature for the given file", GTK_MESSAGE_WARNING);
                } else if (status == GPGME_ERROR || status == FILE_OPEN_ERROR) {
                    show_message_dialog (verify_widgets->main_window, "An error occurred while checking the signature", GTK_MESSAGE_WARNING);
                } else {
                    if (status == SIGNATURE_OK) {
                        show_message_dialog (verify_widgets->main_window, "Signature OK for the given file", GTK_MESSAGE_INFO);
                    } else {
                        show_message_dialog (verify_widgets->main_window, "Signature OK for the given file but the key is not certified with a trusted signature", GTK_MESSAGE_INFO);
                    }
                }
            }
            gtk_widget_destroy (verify_widgets->dialog);
            g_free (verify_widgets->entry_data.entry1_filename);
            g_free (verify_widgets->entry_data.entry2_filename);
            g_free (verify_widgets);
            break;
        default:
            break;
    }
}


static void
cancel_btn_clicked_cb (GtkWidget *btn __attribute__((unused)),
                       gpointer   user_data)
{
    VerifyWidgets *verify_widgets = user_data;

    gtk_widget_destroy (verify_widgets->dialog);

    g_free (verify_widgets);
}


static void
select_file_cb (GtkEntry                *entry,
                GtkEntryIconPosition     icon_pos  __attribute__((unused)),
                GdkEvent                *event __attribute__((unused)),
                gpointer                 user_data)
{
    VerifyWidgets *verify_widgets = user_data;
    GSList *list = choose_file (verify_widgets->main_window, "Choose file", FALSE);
    gchar *filename = get_filename_from_list (list);
    if (filename == NULL) {
        return;
    }

    if (g_strcmp0 (gtk_widget_get_name (GTK_WIDGET (entry)), "signed_file_entry") == 0) {
        verify_widgets->entry_data.entry1_filename = g_strdup (filename);
    } else {
        verify_widgets->entry_data.entry2_filename = g_strdup (filename);

    }
    gtk_entry_set_text (entry, filename);

    g_free (filename);
}


static void
entry_changed_cb (GtkWidget *btn,
                  gpointer   user_data)
{
    VerifyWidgets *verify_widgets = user_data;

    if (g_strcmp0 (gtk_widget_get_name (btn), "signed_file_entry") == 0) {
        verify_widgets->entry_data.entry1_changed = TRUE;
    } else {
        verify_widgets->entry_data.entry2_changed = TRUE;
    }

    if (verify_widgets->entry_data.entry1_changed == TRUE && verify_widgets->entry_data.entry2_changed == TRUE) {
        if (get_file_size (verify_widgets->entry_data.entry2_filename) > MAX_SIG_FILE_SIZE) {
            show_message_dialog (verify_widgets->main_window, "The chosen file is not a detached signature.", GTK_MESSAGE_ERROR);
            gtk_dialog_response (GTK_DIALOG (verify_widgets->dialog), GTK_RESPONSE_DELETE_EVENT);
        } else {
            ThreadData *thread_data = g_new0 (ThreadData, 1);
            thread_data->dialog = verify_widgets->dialog;
            thread_data->spinner = verify_widgets->spinner;
            thread_data->message_label = verify_widgets->message_label;
            thread_data->signed_file = verify_widgets->entry_data.entry1_filename;
            thread_data->signature_file = verify_widgets->entry_data.entry2_filename;

            gtk_widget_show (thread_data->spinner);
            start_spinner (thread_data->spinner);

            if (gtk_widget_get_sensitive (verify_widgets->signed_file_entry) != FALSE) {
                gtk_widget_set_sensitive (verify_widgets->signed_file_entry, FALSE);
            }
            if (gtk_widget_get_sensitive (verify_widgets->signature_file_entry) != FALSE) {
                gtk_widget_set_sensitive (verify_widgets->signature_file_entry, FALSE);
            }

            verify_widgets->thread = g_thread_new (NULL, exec_thread, thread_data);
        }
    }
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
static gpointer
exec_thread (gpointer user_data)
{
    ThreadData *data = user_data;

    set_label_message (data->message_label, "Checking signature...");
    gpointer status = verify_signature (data->signed_file, data->signature_file);

    gtk_dialog_response (GTK_DIALOG (data->dialog), GTK_RESPONSE_DELETE_EVENT);

    g_free (data);

    g_thread_exit (status);
} //-V591
#pragma GCC diagnostic pop
