#include <gtk/gtk.h>
#include "main.h"

void compare_files_hash_cb (GtkWidget __attribute__((__unused__)) *button, gpointer user_data)
{
    AppWidgets *widgets = user_data;
    GtkDialogFlags flags = GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT;
    GtkWidget *dialog = gtk_dialog_new_with_buttons ("Compare files hash", GTK_WINDOW (widgets->main_window), flags,
                                                     "Cancel", GTK_RESPONSE_CANCEL, NULL);
    GtkWidget *content_area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));

    GtkWidget *grid = gtk_grid_new ();
    gtk_container_add (GTK_CONTAINER (content_area), grid);

    GtkWidget *file1_hash = gtk_entry_new ();
    GtkWidget *file2_hash = gtk_entry_new ();
    gtk_editable_set_editable (GTK_EDITABLE (file1_hash), FALSE);
    gtk_editable_set_editable (GTK_EDITABLE (file2_hash), FALSE);

    GtkWidget *select_file1_btn = gtk_button_new_from_icon_name ("document-open", GTK_ICON_SIZE_MENU);
    GtkWidget *select_file2_btn = gtk_button_new_from_icon_name ("document-open", GTK_ICON_SIZE_MENU);

    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_set_column_spacing (GTK_GRID (grid), 5);
    gtk_grid_attach (GTK_GRID (grid), file1_hash, 0, 0, 4, 1);
    gtk_grid_attach (GTK_GRID (grid), file2_hash, 0, 1, 4, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), select_file1_btn, file1_hash, GTK_POS_RIGHT, 1, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), select_file2_btn, file2_hash, GTK_POS_RIGHT, 1, 1);

    gtk_widget_show_all (dialog);

    gint result = gtk_dialog_run (GTK_DIALOG (dialog));
    switch (result) {
        case GTK_RESPONSE_CANCEL:
            gtk_widget_destroy (dialog);
            break;
        default:
            break;
    }

    /* TODO
     * - select file_1
     * - select file_2
     * - compute md5 and sha1 of the above files
     * - display md5+sha1 of file_1 and file_2
     * - if hashes are different then bg color will become red
     */
    return;
}
