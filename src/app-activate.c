#include <gtk/gtk.h>
#include <gcrypt.h>
#include "main.h"
#include "gtkcrypto.h"

void
activate (GtkApplication *app,
          gpointer __attribute__((__unused__)) data)
{
    AppWidgets *widgets = g_new0(struct _widgets, 1);

    GtkWidget *button[NUM_OF_BUTTONS];
    GtkWidget *frame[2];
    GtkWidget *box[2];
    GtkWidget *grid;

    gint i, j = 0;
    const gchar *button_label[] = {"File", "Text", "Compute Hash", "Quit"};
    const gchar *frame_label[] = {"Encrypt", "Decrypt"};
    const gchar *button_name[] = {"butEn", "butDe", "butEnTxt", "butDeTxt", "butHa", "butQ"}; //button 0,1,2,3,4,5

    widgets->main_window = create_main_window(app);

    gtk_application_add_window (GTK_APPLICATION (app), GTK_WINDOW (main_var->main_window));

    if (!gcry_check_version("1.7.0")) {
        show_message_dialog(main_var->main_window, "The required version of Gcrypt is 1.7.0 or greater."), GTK_MESSAGE_ERROR);
        return;
    }

    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    for (i = 0; i < NUM_OF_BUTTONS; i++) {
        if (i == 5)
            j++;

        button[i] = gtk_button_new_with_label(button_label[j]);
        gtk_widget_set_name(GTK_WIDGET(button[i]), button_name[i]);

        if (i % 2 != 0)
            j++;
    }

    for (i = 0; i < NUM_OF_FRAMES; i++)
        frame[i] = gtk_frame_new(frame_label[i]);

    for (i = 0; i < NUM_OF_BOXES; i++)
        box[i] = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);

    gtk_box_pack_start(GTK_BOX(box[0]), button[0], TRUE, TRUE, 2);
    gtk_box_pack_start(GTK_BOX(box[0]), button[2], TRUE, TRUE, 2);
    gtk_container_add(GTK_CONTAINER(frame[0]), box[0]);

    gtk_box_pack_start(GTK_BOX(box[1]), button[1], TRUE, TRUE, 2);
    gtk_box_pack_start(GTK_BOX(box[1]), button[3], TRUE, TRUE, 2);
    gtk_container_add(GTK_CONTAINER(frame[1]), box[1]);

    GValue bottom_margin = G_VALUE_INIT;
    if (!G_IS_VALUE(&bottom_margin))
        g_value_init(&bottom_margin, G_TYPE_UINT);
    g_value_set_uint(&bottom_margin, 2);
    for (i = 0; i < NUM_OF_BUTTONS; i++)
        g_object_set_property(G_OBJECT(button[i]), "margin-bottom", &bottom_margin);

    g_signal_connect(button[0], "clicked", G_CALLBACK(choose_file_dialog), main_var);
    g_signal_connect(button[1], "clicked", G_CALLBACK(choose_file_dialog), main_var);
    g_signal_connect(button[2], "clicked", G_CALLBACK(text_dialog), main_var->main_window);
    g_signal_connect(button[3], "clicked", G_CALLBACK(text_dialog), main_var->main_window);
    g_signal_connect(button[4], "clicked", G_CALLBACK(choose_file_dialog), main_var);
    g_signal_connect(button[5], "clicked", G_CALLBACK(quit), app);

    grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER(main_var->main_window), grid);
    gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 5);

    gtk_grid_attach(GTK_GRID(grid), frame[0], 0, 0, 3, 2);
    gtk_grid_attach(GTK_GRID(grid), frame[1], 0, 2, 3, 2);
    gtk_grid_attach(GTK_GRID(grid), button[4], 0, 5, 3, 1);
    gtk_grid_attach(GTK_GRID(grid), button[5], 0, 6, 3, 1);

    gtk_widget_show_all(main_var->main_window);
}