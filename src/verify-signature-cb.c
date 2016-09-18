#include <gtk/gtk.h>
#include "common-widgets.h"
#include "gtkcrypto.h"
#include "gpgme-misc.h"
#include "verify-signature-cb.h"

#define MAX_SIG_FILE_SIZE 4096

typedef struct verify_signature_widgets_t {
    GtkWidget *main_window;
    GtkWidget *dialog;
    GtkWidget *ok_btn;
    GtkWidget *cancel_btn;
    GtkWidget *signed_file_entry;
    GtkWidget *signature_file_entry;
    GtkWidget *spinner;
    GtkWidget *message_label;
    struct {
        gchar *entry1_filename;
        gchar *entry2_filename;
        gboolean entry1_changed;
        gboolean entry2_changed;
    } entry_data;
} VerifyWidgets;

typedef struct compare_hash_thread_data_t {
    gchar *filename;
    VerifyWidgets *widgets_data;
} ThreadData;

static void select_file_cb (GtkEntry *entry, GtkEntryIconPosition icon_pos, GdkEvent *event, gpointer user_data);

static void cancel_btn_clicked_cb (GtkWidget *btn, gpointer user_data);

static int check_signature_file (const gchar *sig_file);


void
verify_signature_cb (GtkWidget *btn __attribute__((__unused__)),
                     gpointer user_data)
{
    VerifyWidgets *verify_widgets = g_new0 (VerifyWidgets, 1);

    verify_widgets->entry_data.entry1_changed = FALSE;
    verify_widgets->entry_data.entry2_changed = FALSE;

    verify_widgets->main_window = user_data;

    verify_widgets->dialog = create_dialog (verify_widgets->main_window, "ver_sig_dialog", "Verify Signature");

    verify_widgets->ok_btn = gtk_dialog_add_button (GTK_DIALOG (verify_widgets->dialog), "OK", GTK_RESPONSE_OK);
    verify_widgets->cancel_btn = gtk_dialog_add_button (GTK_DIALOG (verify_widgets->dialog), "Cancel",
                                                        GTK_RESPONSE_CANCEL);
    gtk_widget_set_margin_top (verify_widgets->ok_btn, 10);
    gtk_widget_set_margin_top (verify_widgets->cancel_btn, 10);

    gtk_widget_set_size_request (verify_widgets->dialog, 600, -1);

    verify_widgets->signed_file_entry = gtk_entry_new ();
    gtk_widget_set_name (GTK_WIDGET (verify_widgets->signed_file_entry), "signed_file_entry");
    gtk_entry_set_placeholder_text (GTK_ENTRY (verify_widgets->signed_file_entry), "Choose signed file");
    verify_widgets->signature_file_entry = gtk_entry_new ();
    gtk_widget_set_name (GTK_WIDGET (verify_widgets->signed_file_entry), "signature_file_entry");
    gtk_entry_set_placeholder_text (GTK_ENTRY (verify_widgets->signature_file_entry), "Choose signature (.sig) file");
    gtk_editable_set_editable (GTK_EDITABLE (verify_widgets->signed_file_entry), FALSE);
    gtk_editable_set_editable (GTK_EDITABLE (verify_widgets->signature_file_entry), FALSE);
    gtk_widget_set_hexpand (verify_widgets->signed_file_entry, TRUE);
    gtk_widget_set_hexpand (verify_widgets->signature_file_entry, TRUE);

    gtk_entry_set_icon_from_icon_name (GTK_ENTRY (verify_widgets->signed_file_entry), GTK_ENTRY_ICON_SECONDARY,
                                       "document-open-symbolic");
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

    GtkWidget *hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_end (GTK_BOX(hbox), verify_widgets->ok_btn, TRUE, TRUE, 0);
    gtk_box_pack_end (GTK_BOX(hbox), verify_widgets->cancel_btn, TRUE, TRUE, 0);
    gtk_grid_attach (GTK_GRID (grid), hbox, 0, 3, 4, 1);

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
            gtk_widget_destroy (verify_widgets->dialog);
            g_free (verify_widgets);
            break;
        default:
            break;
    }
}


static void
select_file_cb (GtkEntry *entry,
                GtkEntryIconPosition icon_pos  __attribute__((__unused__)),
                GdkEvent *event __attribute__((__unused__)),
                gpointer user_data)
{
    VerifyWidgets *verify_widgets = user_data;

    gchar *filename = choose_file (verify_widgets->main_window, "Choose file");

    if (gtk_widget_get_name (GTK_WIDGET (entry)) == "signed_file_entry") {
        verify_widgets->entry_data.entry1_filename = g_strdup (filename);
    }
    else {
        verify_widgets->entry_data.entry2_filename = g_strdup (filename);
    }

    g_free (filename);
}


static void
entry_changed_cb (GtkWidget *btn, gpointer user_data)
{
    VerifyWidgets *verify_widgets = user_data;

    if (g_strcmp0 (gtk_widget_get_name (btn), "signed_file_entry") == 0) {
        verify_widgets->entry_data.entry1_changed = TRUE;
    }
    else {
        verify_widgets->entry_data.entry2_changed = TRUE;
    }

    if (verify_widgets->entry_data.entry1_changed == TRUE &&verify_widgets->entry_data.entry2_changed == TRUE) {
        gint err = check_signature_file (verify_widgets->entry_data.entry2_filename);
        if (err == FILE_TOO_BIG) {
            //TODO
        }
        else if (err == MISSING_SIG_EXT) {
            //TODO
        }
        else {
            //TODO
        }
    }
}


static int
check_signature_file (const gchar *signature_file)
{
    goffset sig_file_size = get_file_size (signature_file);
    if (sig_file_size > MAX_SIG_FILE_SIZE) {
        return FILE_TOO_BIG;
    }

    if (!file_has_extension (signature_file, ".sig")) {
        return MISSING_SIG_EXT;
    }

    return SIG_FILE_OK;
}


static void
cancel_btn_clicked_cb ( GtkWidget *btn __attribute__((__unused__)),
                        gpointer user_data)
{
    VerifyWidgets *verify_widgets = user_data;

    gtk_widget_destroy (verify_widgets->dialog);

    g_free (verify_widgets);
}