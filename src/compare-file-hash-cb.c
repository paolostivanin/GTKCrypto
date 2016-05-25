#include <gtk/gtk.h>
#include "main.h"
#include "gtkcrypto.h"
#include "common-callbacks.h"

static void  select_file_cb (GtkWidget *, gpointer);

static void create_header_bar (GtkWidget *, AppWidgets *);

static GtkWidget *create_popover (GtkWidget *, GtkPositionType, AppWidgets *);


void compare_files_hash_cb (GtkWidget __attribute__((__unused__)) *button, gpointer user_data)
{
    AppWidgets *widgets = user_data;
    GtkWidget *dialog = gtk_dialog_new ();
    gtk_widget_set_name (dialog, "dialog");
    gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (widgets->main_window));
    gtk_window_set_destroy_with_parent (GTK_WINDOW (dialog), TRUE);
    GtkWidget *cancel_btn = gtk_dialog_add_button (GTK_DIALOG (dialog), "Cancel", GTK_RESPONSE_CANCEL);
    gtk_widget_set_margin_top (cancel_btn, 10);
    gtk_widget_set_size_request (dialog, 600, -1);

    create_header_bar (dialog, widgets);

    GtkWidget *content_area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
    GtkWidget *grid = gtk_grid_new ();
    gtk_container_add (GTK_CONTAINER (content_area), grid);

    GtkWidget *file1_hash = gtk_entry_new ();
    GtkWidget *file2_hash = gtk_entry_new ();
    gtk_editable_set_editable (GTK_EDITABLE (file1_hash), FALSE);
    gtk_editable_set_editable (GTK_EDITABLE (file2_hash), FALSE);
    gtk_widget_set_hexpand (file1_hash, TRUE);
    gtk_widget_set_hexpand (file2_hash, TRUE);

    GError *err = NULL;
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_path(css, "./css/entry.css", &err);
    if (err != NULL) {
        g_printerr("%s\n", err->message);
    }

    GtkWidget *select_file1_btn = gtk_button_new_from_icon_name ("document-open", GTK_ICON_SIZE_MENU);
    GtkWidget *select_file2_btn = gtk_button_new_from_icon_name ("document-open", GTK_ICON_SIZE_MENU);

    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_set_column_spacing (GTK_GRID (grid), 5);
    gtk_grid_attach (GTK_GRID (grid), file1_hash, 0, 0, 4, 1);
    gtk_grid_attach (GTK_GRID (grid), file2_hash, 0, 1, 4, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), select_file1_btn, file1_hash, GTK_POS_RIGHT, 1, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), select_file2_btn, file2_hash, GTK_POS_RIGHT, 1, 1);

    g_signal_connect (select_file1_btn, "clicked", G_CALLBACK (select_file_cb), widgets->main_window);
    g_signal_connect (select_file2_btn, "clicked", G_CALLBACK (select_file_cb), widgets->main_window);
    g_signal_connect_swapped (dialog, "button-press-event", G_CALLBACK (toggle_active_cb), widgets->header_bar_menu);

    gtk_widget_show_all (dialog);

    gint result = gtk_dialog_run (GTK_DIALOG (dialog));
    switch (result) {
        case GTK_RESPONSE_CANCEL:
            gtk_widget_destroy (dialog);
            break;
        default:
            break;
    }
}


static void
select_file_cb (GtkWidget __attribute((__unused__)) *button, gpointer user_data)
{
    GtkWidget *main_window = user_data;
    gchar *filename = choose_file (main_window);

    // TODO threaded computation
    // TODO change bg color (red if mismatch)

    g_free (filename);
}


static void
create_header_bar (GtkWidget *dialog, AppWidgets *widgets)
{
    GtkWidget *header_bar = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button (GTK_HEADER_BAR (header_bar), FALSE);
    gtk_header_bar_set_title (GTK_HEADER_BAR (header_bar), "Compare files hash");
    gtk_header_bar_set_has_subtitle (GTK_HEADER_BAR (header_bar), FALSE);
    gtk_window_set_titlebar (GTK_WINDOW (dialog), header_bar);

    GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_style_context_add_class (gtk_widget_get_style_context (box), "linked");
    GIcon *icon = g_themed_icon_new ("emblem-system-symbolic");
    GtkWidget *image = gtk_image_new_from_gicon (icon, GTK_ICON_SIZE_BUTTON);
    g_object_unref (icon);

    widgets->header_bar_menu = gtk_toggle_button_new();
    gtk_container_add (GTK_CONTAINER (widgets->header_bar_menu), image);
    gtk_widget_set_tooltip_text (GTK_WIDGET (widgets->header_bar_menu), "Settings");

    GtkWidget *popover = create_popover (widgets->header_bar_menu, GTK_POS_TOP, widgets);
    gtk_popover_set_modal (GTK_POPOVER (popover), TRUE);
    g_signal_connect (widgets->header_bar_menu, "toggled", G_CALLBACK (toggle_changed_cb), popover);

    gtk_header_bar_pack_start (GTK_HEADER_BAR (header_bar), GTK_WIDGET (widgets->header_bar_menu));
}


static GtkWidget *
create_popover (GtkWidget *parent, GtkPositionType pos, AppWidgets *widgets)
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

    gint i, j;

    widgets->radio_button[0] = gtk_radio_button_new_with_label_from_widget (NULL, algo[0]);
    for (i = 1, j = 1; i < RADIO_BTN; i++, j++)
        widgets->radio_button[i] = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON (widgets->radio_button[0]), algo[j]);

    for (i = 0; i < 2; i++)
        gtk_box_pack_start (GTK_BOX (box[0]), widgets->radio_button[i], TRUE, TRUE, 0);

    for (i = 2; i < 4; i++)
        gtk_box_pack_start (GTK_BOX (box[1]), widgets->radio_button[i], FALSE, TRUE, 0);

    for (i = 4; i < RADIO_BTN; i++)
        gtk_box_pack_start (GTK_BOX (box[2]), widgets->radio_button[i], FALSE, TRUE, 0);

    GtkWidget *vline1 = gtk_separator_new (GTK_ORIENTATION_VERTICAL);
    GtkWidget *vline2 = gtk_separator_new (GTK_ORIENTATION_VERTICAL);

    gtk_box_pack_start (GTK_BOX (box[3]), box[0], FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (box[3]), vline1, TRUE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (box[3]), box[1], FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (box[3]), vline2, TRUE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (box[3]), box[2], FALSE, FALSE, 0);

    for (i = 0; i < RADIO_BTN; i++)
        g_signal_connect_swapped (widgets->radio_button[i], "clicked", G_CALLBACK (toggle_active_cb),
                                  widgets->header_bar_menu);

    g_object_set (widgets->radio_button[0], "active", TRUE, NULL);

    gtk_container_add (GTK_CONTAINER (popover), box[3]);
    gtk_container_set_border_width (GTK_CONTAINER (popover), 4);
    gtk_widget_show_all (box[3]);

    return popover;
}