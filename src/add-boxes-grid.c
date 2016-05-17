#include <gtk/gtk.h>
#include "main.h"

#define NUM_OF_BUTTONS 5
#define NUM_OF_FRAMES 2
#define NUM_OF_BOXES 2

void
add_boxes_and_grid (AppWidgets *widgets) {
    GtkWidget *button[NUM_OF_BUTTONS];
    GtkWidget *frame[NUM_OF_FRAMES];
    GtkWidget *box[NUM_OF_BOXES];

    gint i, j = 0;
    const gchar *button_label[] = {"File", "Text", "Compute Hash", "Quit"};
    const gchar *frame_label[] = {"Encrypt", "Decrypt"};
    const gchar *button_name[] = {"enc_btn", "dec_btn", "enc_txt_btn", "dec_txt_btn", "hash_btn", "quit_btn"};

    for (i = 0; i < NUM_OF_BUTTONS; i++) {
        if (i == 5)
            j++;

        button[i] = gtk_button_new_with_label (button_label[j]);
        gtk_widget_set_name (GTK_WIDGET (button[i]), button_name[i]);

        if (i % 2 != 0)
            j++;
    }

    for (i = 0; i < NUM_OF_FRAMES; i++)
        frame[i] = gtk_frame_new (frame_label[i]);

    for (i = 0; i < NUM_OF_BOXES; i++)
        box[i] = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 2);

    gtk_box_pack_start (GTK_BOX (box[0]), button[0], TRUE, TRUE, 2);
    gtk_box_pack_start (GTK_BOX (box[0]), button[2], TRUE, TRUE, 2);
    gtk_container_add (GTK_CONTAINER (frame[0]), box[0]);

    gtk_box_pack_start (GTK_BOX (box[1]), button[1], TRUE, TRUE, 2);
    gtk_box_pack_start (GTK_BOX (box[1]), button[3], TRUE, TRUE, 2);
    gtk_container_add (GTK_CONTAINER (frame[1]), box[1]);

    GValue bottom_margin = G_VALUE_INIT;
    if (!G_IS_VALUE (&bottom_margin))
        g_value_init (&bottom_margin, G_TYPE_UINT);
    g_value_set_uint (&bottom_margin, 2);

    for (i = 0; i < NUM_OF_BUTTONS; i++)
        g_object_set_property (G_OBJECT (button[i]), "margin-bottom", &bottom_margin);

    //g_signal_connect(button[0], "clicked", G_CALLBACK(choose_file_dialog), widgets);
    //g_signal_connect(button[1], "clicked", G_CALLBACK(choose_file_dialog), widgets);
    //g_signal_connect(button[2], "clicked", G_CALLBACK(text_dialog), widgets->main_window);
    //g_signal_connect(button[3], "clicked", G_CALLBACK(text_dialog), widgets->main_window);
    //g_signal_connect(button[4], "clicked", G_CALLBACK(choose_file_dialog), widgets);

    GtkWidget *grid = gtk_grid_new ();
    gtk_container_add (GTK_CONTAINER (widgets->main_window), grid);
    gtk_grid_set_row_homogeneous (GTK_GRID (grid), TRUE);
    gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);
    gtk_grid_set_row_spacing (GTK_GRID (grid), 5);
    gtk_grid_set_column_spacing (GTK_GRID (grid), 5);

    gtk_grid_attach (GTK_GRID (grid), frame[0], 0, 0, 3, 2);
    gtk_grid_attach (GTK_GRID (grid), frame[1], 0, 2, 3, 2);
    gtk_grid_attach (GTK_GRID (grid), button[4], 0, 5, 3, 1);
}