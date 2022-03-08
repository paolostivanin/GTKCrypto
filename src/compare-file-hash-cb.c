#include <gtk/gtk.h>
#include <gcrypt.h>
#include "gtkcrypto.h"
#include "common-callbacks.h"
#include "common-widgets.h"
#include "hash.h"
#include "misc-style.h"


typedef struct compare_hash_widgets_t {
    GtkWidget *main_window;
    GtkWidget *cancel_btn;
    GtkWidget *radio_button[6];
    GtkWidget *header_bar_menu;
    GtkWidget *file1_hash_entry;
    GtkWidget *file2_hash_entry;
    GtkWidget *spinner_entry1;
    GtkWidget *spinner_entry2;
    gboolean entry1_changed;
    gboolean entry2_changed;
} HashWidgets;

typedef struct compare_hash_thread_data_t {
    GtkEntry *entry;
    gchar *filename;
    gint hash_algo;
    gint digest_size;
    HashWidgets *widgets_data;
} ThreadData;

static void       select_file_cb    (GtkEntry             *entry,
                                     GtkEntryIconPosition  icon_pos,
                                     GdkEvent             *event,
                                     gpointer              user_data);

static void       do_header_bar     (GtkWidget   *dialog,
                                     HashWidgets *widgets);

static GtkWidget *create_popover    (GtkWidget       *parent,
                                     GtkPositionType  pos,
                                     HashWidgets     *widgets);

static void       entry_changed_cb  (GtkWidget *btn,
                                     gpointer   user_data);

static gpointer   exec_thread       (gpointer);


void
compare_files_hash_cb (GtkWidget *button  __attribute__((unused)),
                       gpointer   user_data)
{
    HashWidgets *hash_widgets = g_new0 (HashWidgets, 1);
    hash_widgets->main_window = (GtkWidget *)user_data;
    hash_widgets->entry1_changed = FALSE;
    hash_widgets->entry2_changed = FALSE;

    GtkWidget *dialog = create_dialog (hash_widgets->main_window, "dialog", NULL);
    hash_widgets->cancel_btn = gtk_dialog_add_button (GTK_DIALOG (dialog), "Cancel", GTK_RESPONSE_CANCEL);
    gtk_widget_set_margin_top (hash_widgets->cancel_btn, 10);
    gtk_widget_set_size_request (dialog, 600, -1);

    do_header_bar (dialog, hash_widgets);

    GtkWidget *content_area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
    GtkWidget *grid = gtk_grid_new ();
    gtk_container_add (GTK_CONTAINER (content_area), grid);

    hash_widgets->file1_hash_entry = gtk_entry_new ();
    gtk_widget_set_name (hash_widgets->file1_hash_entry, "file1_he_name");
    hash_widgets->file2_hash_entry = gtk_entry_new ();
    gtk_widget_set_name (hash_widgets->file2_hash_entry, "file2_he_name");
    gtk_editable_set_editable (GTK_EDITABLE (hash_widgets->file1_hash_entry), FALSE);
    gtk_editable_set_editable (GTK_EDITABLE (hash_widgets->file2_hash_entry), FALSE);
    gtk_widget_set_hexpand (hash_widgets->file1_hash_entry, TRUE);
    gtk_widget_set_hexpand (hash_widgets->file2_hash_entry, TRUE);

    PangoData *pango_data = get_pango_monospace_attr ();
    gtk_entry_set_attributes (GTK_ENTRY (hash_widgets->file1_hash_entry), pango_data->attrs);
    gtk_entry_set_attributes (GTK_ENTRY (hash_widgets->file2_hash_entry), pango_data->attrs);

    gtk_entry_set_icon_from_icon_name (GTK_ENTRY (hash_widgets->file1_hash_entry), GTK_ENTRY_ICON_SECONDARY, "document-open-symbolic");
    gtk_entry_set_icon_from_icon_name (GTK_ENTRY (hash_widgets->file2_hash_entry), GTK_ENTRY_ICON_SECONDARY, "document-open-symbolic");

    hash_widgets->spinner_entry1 = create_spinner();
    hash_widgets->spinner_entry2 = create_spinner();

    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_set_column_spacing (GTK_GRID (grid), 5);
    gtk_grid_attach (GTK_GRID (grid), hash_widgets->file1_hash_entry, 0, 1, 4, 1);
    gtk_grid_attach (GTK_GRID (grid), hash_widgets->file2_hash_entry, 0, 2, 4, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), hash_widgets->spinner_entry1, hash_widgets->file1_hash_entry, GTK_POS_RIGHT, 1, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), hash_widgets->spinner_entry2, hash_widgets->file2_hash_entry, GTK_POS_RIGHT, 1, 1);

    g_signal_connect (hash_widgets->file1_hash_entry, "icon-press", G_CALLBACK (select_file_cb), hash_widgets);
    g_signal_connect (hash_widgets->file2_hash_entry, "icon-press", G_CALLBACK (select_file_cb), hash_widgets);
    g_signal_connect_swapped (dialog, "button-press-event", G_CALLBACK (toggle_active_cb),
                              hash_widgets->header_bar_menu);
    g_signal_connect (hash_widgets->file1_hash_entry, "changed", G_CALLBACK (entry_changed_cb), hash_widgets);
    g_signal_connect (hash_widgets->file2_hash_entry, "changed", G_CALLBACK (entry_changed_cb), hash_widgets);

    gtk_widget_show_all (dialog);

    gint result = gtk_dialog_run (GTK_DIALOG (dialog));
    switch (result) {
        case GTK_RESPONSE_CANCEL:
            gtk_widget_destroy (dialog);
            pango_data_free (pango_data);
            g_free (hash_widgets);
            break;
        default:
            break;
    }
}


static void
select_file_cb (GtkEntry             *entry,
                GtkEntryIconPosition  icon_pos  __attribute__((unused)),
                GdkEvent             *event     __attribute__((unused)),
                gpointer              user_data)
{
    ThreadData *thread_data = g_new0 (ThreadData, 1);
    HashWidgets *hash_widgets = user_data;
    thread_data->widgets_data = hash_widgets;

    GSList *list = choose_file (hash_widgets->main_window, "Pick file to compare", FALSE);
    gchar *filename = get_filename_from_list (list);
    if (filename == NULL) {
        g_free (thread_data);
        return;
    }

    gint hash_algo = -1, digest_size = -1;
    for (gint i = 0; i < 6; i++) {
        if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (hash_widgets->radio_button[i]))) {
            if (g_strcmp0 (gtk_widget_get_name (hash_widgets->radio_button[i]), "md5_radio_btn") == 0) {
                hash_algo = GCRY_MD_MD5;
                digest_size = MD5_DIGEST_SIZE;
            }
            else if (g_strcmp0 (gtk_widget_get_name (hash_widgets->radio_button[i]), "sha1_radio_btn") == 0) {
                hash_algo = GCRY_MD_SHA1;
                digest_size = SHA1_DIGEST_SIZE;
            }
            else if (g_strcmp0 (gtk_widget_get_name (hash_widgets->radio_button[i]), "sha256_radio_btn") == 0) {
                hash_algo = GCRY_MD_SHA256;
                digest_size = SHA256_DIGEST_SIZE;
            }
            else if (g_strcmp0 (gtk_widget_get_name (hash_widgets->radio_button[i]), "sha512_radio_btn") == 0) {
                hash_algo = GCRY_MD_SHA512;
                digest_size = SHA512_DIGEST_SIZE;
            }
            else if (g_strcmp0 (gtk_widget_get_name (hash_widgets->radio_button[i]), "sha3_256_radio_btn") == 0) {
                hash_algo = GCRY_MD_SHA3_256;
                digest_size = SHA3_256_DIGEST_SIZE;
            }
            else if (g_strcmp0 (gtk_widget_get_name (hash_widgets->radio_button[i]), "sha3_512_radio_btn") == 0) {
                hash_algo = GCRY_MD_SHA3_512;
                digest_size = SHA3_512_DIGEST_SIZE;
            }
        }
    }

    thread_data->entry = entry;
    thread_data->digest_size = digest_size;
    thread_data->hash_algo = hash_algo;
    thread_data->filename = filename;

    if (g_strcmp0 (gtk_widget_get_name (GTK_WIDGET (entry)), "file1_he_name") == 0) {
        start_spinner (hash_widgets->spinner_entry1);
    }
    else {
        start_spinner (hash_widgets->spinner_entry2);
    }

    g_thread_new (NULL, exec_thread, thread_data);
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
static gpointer
exec_thread (gpointer user_data)
{
    ThreadData *data = user_data;

    if (gtk_widget_get_sensitive (data->widgets_data->cancel_btn)) {
        gtk_widget_set_sensitive (data->widgets_data->cancel_btn, FALSE);
    }

    gchar *hash = get_file_hash (data->filename, data->hash_algo, data->digest_size);
    if (hash == NULL) {
        show_message_dialog (data->widgets_data->main_window, "Error during hash computation", GTK_MESSAGE_ERROR);
        g_free (data->filename);
        g_free (data);
        g_thread_exit (NULL);
    }

    if (g_strcmp0 (gtk_widget_get_name (GTK_WIDGET (data->entry)), "file1_he_name") == 0) { //-V774
        gtk_entry_set_text (GTK_ENTRY (data->widgets_data->file1_hash_entry), hash); //-V774
        stop_spinner (data->widgets_data->spinner_entry1); //-V774
    }
    else {
        gtk_entry_set_text (GTK_ENTRY (data->widgets_data->file2_hash_entry), hash); //-V774
        stop_spinner (data->widgets_data->spinner_entry2); //-V774
    }

    if (!gtk_widget_get_sensitive (data->widgets_data->cancel_btn)) { //-V774
        /* if cancel_btn is non-sensitive AND both the gtk_entry have have text inside them, THEN cancel_btn becomes
         + sensitive again. */
        if ((data->widgets_data->entry1_changed) && (data->widgets_data->entry2_changed)) { //-V774
            gtk_widget_set_sensitive (data->widgets_data->cancel_btn, TRUE); //-V774
        }
    }
    g_free (data->filename); //-V774
    g_free (hash);
    g_free (data); //-V586
    g_thread_exit ((gpointer) 0);
} //-V591
#pragma GCC diagnostic pop


static void
do_header_bar (GtkWidget   *dialog,
               HashWidgets *widgets)
{
    GtkWidget *header_bar = create_header_bar (dialog, "Compare Hash");

    GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_style_context_add_class (gtk_widget_get_style_context (box), "linked");
    GIcon *icon = g_themed_icon_new ("emblem-system-symbolic");
    GtkWidget *image = gtk_image_new_from_gicon (icon, GTK_ICON_SIZE_BUTTON);
    g_object_unref (icon);

    widgets->header_bar_menu = gtk_toggle_button_new ();
    gtk_container_add (GTK_CONTAINER (widgets->header_bar_menu), image);
    gtk_widget_set_tooltip_text (GTK_WIDGET (widgets->header_bar_menu), "Settings");

    GtkWidget *popover = create_popover (widgets->header_bar_menu, GTK_POS_TOP, widgets);
    gtk_popover_set_modal (GTK_POPOVER (popover), TRUE);
    g_signal_connect (widgets->header_bar_menu, "toggled", G_CALLBACK (toggle_changed_cb), popover);

    gtk_header_bar_pack_start (GTK_HEADER_BAR (header_bar), GTK_WIDGET (widgets->header_bar_menu));
}


static GtkWidget *
create_popover (GtkWidget       *parent,
                GtkPositionType  pos,
                HashWidgets     *widgets)
{
    const gchar *algo[] = {"MD5", "SHA1", "SHA2-256", "SHA2-512", "SHA3-256", "SHA3-512"};

    GtkWidget *box[4];
    box[0] = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
    box[1] = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
    box[2] = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
    box[3] = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);

    gtk_box_set_homogeneous (GTK_BOX (box[3]), FALSE);

    GtkWidget *popover = gtk_popover_new (parent);
    gtk_popover_set_position (GTK_POPOVER (popover), pos);

    widgets->radio_button[0] = gtk_radio_button_new_with_label_from_widget (NULL, algo[0]);
    for (gint i = 1, j = 1; i < 6; i++, j++) {
        widgets->radio_button[i] = gtk_radio_button_new_with_label_from_widget(
                GTK_RADIO_BUTTON (widgets->radio_button[0]), algo[j]);
    }

    gtk_widget_set_name (widgets->radio_button[0], "md5_radio_btn");
    gtk_widget_set_name (widgets->radio_button[1], "sha1_radio_btn");
    gtk_widget_set_name (widgets->radio_button[2], "sha256_radio_btn");
    gtk_widget_set_name (widgets->radio_button[3], "sha512_radio_btn");
    gtk_widget_set_name (widgets->radio_button[4], "sha3_256_radio_btn");
    gtk_widget_set_name (widgets->radio_button[5], "sha3_512_radio_btn");

    for (gint i = 0; i < 2; i++)
        gtk_box_pack_start (GTK_BOX (box[0]), widgets->radio_button[i], TRUE, TRUE, 0);

    for (gint i = 2; i < 4; i++)
        gtk_box_pack_start (GTK_BOX (box[1]), widgets->radio_button[i], FALSE, TRUE, 0);

    for (gint i = 4; i < 6; i++)
        gtk_box_pack_start (GTK_BOX (box[2]), widgets->radio_button[i], FALSE, TRUE, 0);

    GtkWidget *vline1 = gtk_separator_new (GTK_ORIENTATION_VERTICAL);
    GtkWidget *vline2 = gtk_separator_new (GTK_ORIENTATION_VERTICAL);

    gtk_box_pack_start (GTK_BOX (box[3]), box[0], FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (box[3]), vline1, TRUE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (box[3]), box[1], FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (box[3]), vline2, TRUE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (box[3]), box[2], FALSE, FALSE, 0);

    for (gint i = 0; i < 6; i++) {
        g_signal_connect_swapped (widgets->radio_button[i], "clicked", G_CALLBACK(toggle_active_cb),
                                  widgets->header_bar_menu);
    }

    g_object_set (widgets->radio_button[0], "active", TRUE, NULL);

    gtk_container_add (GTK_CONTAINER (popover), box[3]);
    gtk_container_set_border_width (GTK_CONTAINER (popover), 4);
    gtk_widget_show_all (box[3]);

    return popover;
}


static void
entry_changed_cb (GtkWidget *btn,
                  gpointer   user_data)
{
    HashWidgets *data = user_data;

    if (g_strcmp0 (gtk_widget_get_name (btn), "file1_he_name") == 0) {
        data->entry1_changed = TRUE;
    }
    else {
        data->entry2_changed = TRUE;
    }

    if (data->entry1_changed == TRUE && data->entry2_changed == TRUE) {
        const gchar *hash1 = gtk_entry_get_text (GTK_ENTRY (data->file1_hash_entry));
        const gchar *hash2 = gtk_entry_get_text (GTK_ENTRY (data->file2_hash_entry));

        if (g_strcmp0 (hash1, hash2) != 0) {
            set_css (HASH_ERR_CSS, data->file1_hash_entry);
            set_css (HASH_ERR_CSS, data->file2_hash_entry);
        } else {
            set_css (HASH_OK_CSS, data->file1_hash_entry);
            set_css (HASH_OK_CSS, data->file2_hash_entry);
        }
    }
}