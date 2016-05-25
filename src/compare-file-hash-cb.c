#include <gtk/gtk.h>
#include "main.h"
#include "gtkcrypto.h"

static void  select_file_cb (GtkWidget *, gpointer);

void compare_files_hash_cb (GtkWidget __attribute__((__unused__)) *button, gpointer user_data)
{
    AppWidgets *widgets = user_data;
    GtkWidget *dialog = gtk_dialog_new ();
    gtk_window_set_title (GTK_WINDOW (dialog), "Compare files hash");
    gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (widgets->main_window));
    gtk_window_set_destroy_with_parent (GTK_WINDOW (dialog), TRUE);
    GtkWidget *cancel_btn = gtk_dialog_add_button (GTK_DIALOG (dialog), "Cancel", GTK_RESPONSE_CANCEL);
    gtk_widget_set_margin_top (cancel_btn, 10);
    gtk_widget_set_size_request (dialog, 600, -1);

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

    // TODO headerbar + popover with which one can choose which algo to use?
    // TODO threaded computation
    // TODO change bg color (red if mismatch)

    g_free (filename);
}