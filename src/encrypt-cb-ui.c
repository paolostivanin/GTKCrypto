#include <gtk/gtk.h>
#include "gtkcrypto.h"
#include "common-widgets.h"
#include "encrypt-cb-ui.h"
#include "common-callbacks.h"

void
do_dialog (EncryptWidgets *encrypt_widgets)
{
    encrypt_widgets->dialog = create_dialog (encrypt_widgets->main_window, "enc_dialog", NULL);
    encrypt_widgets->cancel_btn = gtk_button_new_with_label ("Cancel");
    encrypt_widgets->ok_btn = gtk_button_new_with_label ("OK");
    gtk_widget_set_size_request (encrypt_widgets->dialog, 600, -1);

    do_header_bar (encrypt_widgets->dialog, encrypt_widgets);

    do_entry_widgets (encrypt_widgets);
}


void
do_header_bar (GtkWidget *dialog, EncryptWidgets *encrypt_widgets)
{
    GtkWidget *header_bar = create_header_bar (dialog, "Encrypt File");

    GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_style_context_add_class (gtk_widget_get_style_context (box), "linked");
    GIcon *icon = g_themed_icon_new ("emblem-system-symbolic");
    GtkWidget *image = gtk_image_new_from_gicon (icon, GTK_ICON_SIZE_BUTTON);
    g_object_unref (icon);

    encrypt_widgets->header_bar_menu = gtk_toggle_button_new ();
    gtk_container_add (GTK_CONTAINER (encrypt_widgets->header_bar_menu), image);
    gtk_widget_set_tooltip_text (GTK_WIDGET (encrypt_widgets->header_bar_menu), "Settings");

    GtkWidget *popover = create_popover (encrypt_widgets->header_bar_menu, GTK_POS_BOTTOM, encrypt_widgets);
    gtk_popover_set_modal (GTK_POPOVER (popover), TRUE);
    g_signal_connect (encrypt_widgets->header_bar_menu, "toggled", G_CALLBACK (toggle_changed_cb), popover);
    g_signal_connect_swapped (dialog, "button-press-event", G_CALLBACK (toggle_active_cb), encrypt_widgets->header_bar_menu);

    gtk_header_bar_pack_start (GTK_HEADER_BAR (header_bar), GTK_WIDGET (encrypt_widgets->header_bar_menu));
}


void
do_entry_widgets (EncryptWidgets *encrypt_widgets)
{
    encrypt_widgets->entry_pwd = gtk_entry_new ();
    encrypt_widgets->entry_pwd_retype = gtk_entry_new ();
    gtk_entry_set_placeholder_text (GTK_ENTRY (encrypt_widgets->entry_pwd), "Type password...");
    gtk_entry_set_placeholder_text (GTK_ENTRY (encrypt_widgets->entry_pwd_retype), "Retype password...");
    gtk_entry_set_visibility (GTK_ENTRY (encrypt_widgets->entry_pwd), FALSE);
    gtk_entry_set_visibility (GTK_ENTRY (encrypt_widgets->entry_pwd_retype), FALSE);
    gtk_widget_set_hexpand (encrypt_widgets->entry_pwd, TRUE);
    gtk_widget_set_hexpand (encrypt_widgets->entry_pwd_retype, TRUE);
}


GtkWidget *
create_hbox (EncryptWidgets *encrypt_widgets)
{
    GtkWidget *hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_end (GTK_BOX (hbox), encrypt_widgets->ok_btn, TRUE, TRUE, 0);
    gtk_box_pack_end (GTK_BOX (hbox), encrypt_widgets->cancel_btn, TRUE, TRUE, 0);
    return hbox;
}


GtkWidget *
create_popover (GtkWidget *parent, GtkPositionType pos, gpointer user_data)
{
    EncryptWidgets *encrypt_widgets = user_data;

    const gchar *algo[] = {"AES256", "BLOWFISH", "CAMELLIA256", "CAST5", "SERPENT256", "TWOFISH"};
    const gchar *algo_type[] = {"CBC", "CTR"};

    GtkWidget *popover = gtk_popover_new (parent);
    gtk_popover_set_position (GTK_POPOVER (popover), pos);

    encrypt_widgets->radio_button_algo[0] = gtk_radio_button_new_with_label_from_widget (NULL, algo[0]);
    for (gint i = 1, j = 1; i < AVAILABLE_ALGO; i++, j++) {
        encrypt_widgets->radio_button_algo[i] = gtk_radio_button_new_with_label_from_widget(
                GTK_RADIO_BUTTON (encrypt_widgets->radio_button_algo[0]), algo[j]);
    }

    encrypt_widgets->radio_button_algo_mode[0] = gtk_radio_button_new_with_label_from_widget (NULL, algo_type[0]);
    encrypt_widgets->radio_button_algo_mode[1] = gtk_radio_button_new_with_label_from_widget (
            GTK_RADIO_BUTTON (encrypt_widgets->radio_button_algo_mode[0]), algo_type[1]);

    for (gint i = 0; i < AVAILABLE_ALGO; i++) {
        gtk_widget_set_name (encrypt_widgets->radio_button_algo[i], algo[i]);
    }

    for (gint i = 0; i < AVAILABLE_ALGO_MODE; i++) {
        gtk_widget_set_name (encrypt_widgets->radio_button_algo_mode[i], algo_type[i]);
    }

    GtkWidget *final_box = get_final_box_layout (encrypt_widgets);

    for (gint i = 0; i < AVAILABLE_ALGO; i++) {
        g_signal_connect_swapped (encrypt_widgets->radio_button_algo[i], "clicked", G_CALLBACK (toggle_active_cb),
                                  encrypt_widgets->header_bar_menu);
    }

    for (gint i = 0; i < AVAILABLE_ALGO_MODE; i++) {
        g_signal_connect_swapped (encrypt_widgets->radio_button_algo_mode[i], "clicked", G_CALLBACK(toggle_active_cb),
                                  encrypt_widgets->header_bar_menu);
    }

    g_object_set (encrypt_widgets->radio_button_algo[0], "active", TRUE, NULL);
    g_object_set (encrypt_widgets->radio_button_algo_mode[0], "active", TRUE, NULL);

    gtk_container_add (GTK_CONTAINER (popover), final_box);
    gtk_container_set_border_width (GTK_CONTAINER (popover), 4);

    gtk_widget_show_all (final_box);

    return popover;
}


GtkWidget *
get_final_box_layout (EncryptWidgets *encrypt_widgets)
{
    const gchar *label_data[] = {"Cipher", "Mode"};

    gint num_of_vboxes = 6;
    gint num_of_hboxes = 2;

    GtkWidget *v_box[num_of_vboxes];
    GtkWidget *h_box[num_of_hboxes];

    for (gint i = 0; i < num_of_vboxes; i++) {
        v_box[i] = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
    }

    for (gint i = 0; i < num_of_hboxes; i++) {
        h_box[i] = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
    }

    GtkWidget *label[2], *v_line[2], *h_line[2];
    for (gint i = 0; i < 2; i++) {
        label[i] = gtk_label_new (label_data[i]);
        v_line[i] = gtk_separator_new (GTK_ORIENTATION_VERTICAL);
        h_line[i] = gtk_separator_new (GTK_ORIENTATION_HORIZONTAL);
    }

    // Cipher
    // ------
    gtk_box_pack_start (GTK_BOX (v_box[0]), label[0], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (v_box[0]), h_line[0], FALSE, TRUE, 0);

    // Algo
    for (gint i = 1, j = 0; j < AVAILABLE_ALGO / 2; j++) {
        gtk_box_pack_start (GTK_BOX (v_box[i]), encrypt_widgets->radio_button_algo[j], FALSE, TRUE, 0);
    }

    // Algo
    for (gint i = 2, j = AVAILABLE_ALGO / 2; j < AVAILABLE_ALGO; j++) {
        gtk_box_pack_start (GTK_BOX (v_box[i]), encrypt_widgets->radio_button_algo[j], FALSE, TRUE, 0);
    }

    // Algo | Algo
    gtk_box_pack_start (GTK_BOX (h_box[0]), v_box[1], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (h_box[0]), v_line[0], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (h_box[0]), v_box[2], FALSE, TRUE, 0);

    /*    Cipher
     * -----------
     * Algo | Algo
     */
    gtk_box_pack_start (GTK_BOX (v_box[3]), v_box[0], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (v_box[3]), h_box[0], FALSE, TRUE, 0);

    /*   Mode
     * --------
     * algo mode
     */
    gtk_box_pack_start (GTK_BOX (v_box[4]), label[1], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (v_box[4]), h_line[1], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (v_box[4]), encrypt_widgets->radio_button_algo_mode[0], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (v_box[4]), encrypt_widgets->radio_button_algo_mode[1], FALSE, TRUE, 0);

    // final layout
    gtk_box_pack_start (GTK_BOX (h_box[1]), v_box[3], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (h_box[1]), v_line[1], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (h_box[1]), v_box[4], FALSE, TRUE, 0);

    return h_box[1];
}