#include <gtk/gtk.h>
#include <gtk/gtk.h>
#include <gcrypt.h>
#include "gtkcrypto.h"
#include "common-callbacks.h"
#include "hash.h"


typedef struct compute_hash_widgets_t {
    GtkWidget *main_window;
    GtkWidget *cancel_btn;
    GtkWidget *check_button[AVAILABLE_HASH_TYPE];
    GtkWidget *hash_entry[AVAILABLE_HASH_TYPE];
    GtkWidget *spinner[AVAILABLE_HASH_TYPE];
} HashWidgets;

static void copy_to_clipboard (GtkEntry *, GtkEntryIconPosition icon_pos, GdkEvent *, gpointer);

static void prepare_hash_computation (GtkWidget *, gpointer);


void
compute_hash_cb (GtkWidget __attribute((__unused__)) *button, gpointer user_data)
{
    const gchar *ck_btn_labels[] = {"MD5", "SHA-1", "GOST94", "SHA-256", "SHA3-256", "SHA-384", "SHA3-384",
                                    "SHA-512", "SHA3-512", "WHIRLPOOL"};

    HashWidgets *hash_widgets = g_new0 (HashWidgets, 1);
    hash_widgets->main_window = (GtkWidget *) user_data;

    GtkWidget *dialog = gtk_dialog_new ();
    gtk_widget_set_name (dialog, "dialog");
    gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (hash_widgets->main_window));
    gtk_window_set_destroy_with_parent (GTK_WINDOW (dialog), TRUE);
    gtk_window_set_title (GTK_WINDOW (dialog), "Compute File Hashes");

    hash_widgets->cancel_btn = gtk_dialog_add_button (GTK_DIALOG (dialog), "Cancel", GTK_RESPONSE_CANCEL);
    gtk_widget_set_margin_top (hash_widgets->cancel_btn, 10);
    gtk_widget_set_size_request (dialog, 800, -1);

    gint i;
    for (i = 0; i < AVAILABLE_HASH_TYPE; i++) {
        hash_widgets->check_button[i] = gtk_check_button_new_with_label (ck_btn_labels[i]);
        gtk_widget_set_name (hash_widgets->check_button[i], ck_btn_labels[i]);

        hash_widgets->spinner[i] = create_spinner ();

        hash_widgets->hash_entry[i] = gtk_entry_new ();
        gtk_editable_set_editable (GTK_EDITABLE (hash_widgets->hash_entry[i]), FALSE);
        gtk_widget_set_hexpand (hash_widgets->hash_entry[i], TRUE);

        gtk_entry_set_icon_from_icon_name (GTK_ENTRY (hash_widgets->hash_entry[i]), GTK_ENTRY_ICON_SECONDARY, "edit-copy-symbolic");
        // the tooltip doesn't work...why?!?!
        gtk_entry_set_icon_tooltip_text (GTK_ENTRY (hash_widgets->hash_entry[i]), GTK_ENTRY_ICON_SECONDARY, "Copy to clipboard");

        g_signal_connect (hash_widgets->hash_entry[i], "icon-press", G_CALLBACK (copy_to_clipboard), NULL);
        g_signal_connect (hash_widgets->check_button[i], "toggled", G_CALLBACK (prepare_hash_computation), NULL);
    }

    GtkWidget *content_area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
    GtkWidget *grid = gtk_grid_new ();
    gtk_container_add (GTK_CONTAINER (content_area), grid);
    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_set_column_spacing (GTK_GRID (grid), 5);

    gint j;
    for (i = 0, j = 0; i < AVAILABLE_HASH_TYPE; i++, j++) {
        gtk_grid_attach (GTK_GRID (grid), hash_widgets->check_button[i], 0, j, 1, 1);
        gtk_grid_attach_next_to (GTK_GRID (grid), hash_widgets->hash_entry[i], hash_widgets->check_button[i], GTK_POS_RIGHT, 4, 1);
        gtk_grid_attach_next_to (GTK_GRID (grid), hash_widgets->spinner[i], hash_widgets->hash_entry[i], GTK_POS_RIGHT, 1, 1);
    }

    gtk_widget_show_all (dialog);

    gint result = gtk_dialog_run (GTK_DIALOG (dialog));
    switch (result) {
        case GTK_RESPONSE_CANCEL:
            gtk_widget_destroy (dialog);
            g_free (hash_widgets);
            break;
        default:
            break;
    }
}


static void
copy_to_clipboard (GtkEntry *entry,
                   GtkEntryIconPosition icon_pos  __attribute__((__unused__)),
                   GdkEvent *event __attribute__((__unused__)),
                   gpointer user_data __attribute__((__unused__)))
{
    gtk_editable_select_region (GTK_EDITABLE (entry), 0, -1);
    gtk_editable_copy_clipboard (GTK_EDITABLE (entry));
    gtk_editable_set_position (GTK_EDITABLE (entry), 0);
}


static void
prepare_hash_computation (GtkWidget *ck_btn, gpointer user_data)
{
    return;
}