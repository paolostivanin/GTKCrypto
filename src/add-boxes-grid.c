#include <gtk/gtk.h>
#include "main.h"

#define NUM_OF_BUTTONS 8
#define NUM_OF_WIDGETS 3

void
add_boxes_and_grid (GtkWidget *main_window)
{
    GtkWidget *button[NUM_OF_BUTTONS];
    GtkWidget *frame[NUM_OF_WIDGETS];
    GtkWidget *box[NUM_OF_WIDGETS];

    const gchar *button_label[] = {"Encrypt", "Decrypt", "Sign", "Verify Signature", "Compute", "Compare"};
    const gchar *frame_label[] = {"File", "Text", "Hash"};
    const gchar *button_name[] = {"enc_btn", "dec_file_btn", "sign_file_btn", "ver_sig_btn",
                                  "enc_txt_btn", "dec_txt_btn",
                                  "compute_hash_btn", "compare_hash_btn"};

    gint i;
    for (i = 0; i < NUM_OF_BUTTONS; i++) {
        if (i < 4) {
            button[i] = gtk_button_new_with_label (button_label[i]);
        }
    }

    button[4] = gtk_button_new_with_label (button_label[0]);
    button[5] = gtk_button_new_with_label (button_label[1]);
    button[6] = gtk_button_new_with_label (button_label[4]);
    button[7] = gtk_button_new_with_label (button_label[5]);

    for (i = 0; i < NUM_OF_BUTTONS; i++) {
        gtk_widget_set_name (GTK_WIDGET (button[i]), button_name[i]);
    }

    for (i = 0; i < NUM_OF_WIDGETS; i++) {
        frame[i] = gtk_frame_new (frame_label[i]);
        box[i] = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 2);
        gtk_container_add (GTK_CONTAINER (frame[i]), box[i]);
    }

    for (i = 0; i < NUM_OF_BUTTONS; i++) {
        gtk_widget_set_margin_bottom (button[i], 5);
        if (i < 4) {
            gtk_box_pack_start (GTK_BOX (box[0]), button[i], TRUE, TRUE, 2);
        }
        else if (i >= 4 && i < 6) {
            gtk_box_pack_start (GTK_BOX (box[1]), button[i], TRUE, TRUE, 2);
        }
        else {
            gtk_box_pack_start (GTK_BOX (box[2]), button[i], TRUE, TRUE, 2);
        }
    }

    g_signal_connect (button[0], "clicked", G_CALLBACK (encrypt_files_cb), main_window);
    g_signal_connect (button[1], "clicked", G_CALLBACK (decrypt_files_cb), main_window);
    g_signal_connect (button[2], "clicked", G_CALLBACK (sign_file_cb), main_window);
    g_signal_connect (button[3], "clicked", G_CALLBACK (verify_signature_cb), main_window);
    gtk_widget_set_sensitive (button[4], FALSE);
    gtk_widget_set_sensitive (button[5], FALSE);
    g_signal_connect (button[6], "clicked", G_CALLBACK (compute_hash_cb), main_window);
    g_signal_connect (button[7], "clicked", G_CALLBACK (compare_files_hash_cb), main_window);

    GtkWidget *grid = gtk_grid_new ();
    gtk_container_add (GTK_CONTAINER (main_window), grid);
    gtk_grid_set_row_homogeneous (GTK_GRID (grid), TRUE);
    gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);
    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_set_column_spacing (GTK_GRID (grid), 5);

    gtk_grid_attach (GTK_GRID (grid), frame[0], 0, 0, 3, 2);
    gtk_grid_attach (GTK_GRID (grid), frame[1], 0, 2, 3, 2);
    gtk_grid_attach (GTK_GRID (grid), frame[2], 0, 4, 3, 2);
}