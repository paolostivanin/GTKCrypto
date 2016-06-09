#include <gtk/gtk.h>
#include <gcrypt.h>
#include "gtkcrypto.h"
#include "common-widgets.h"
#include "common-callbacks.h"

#define AVAILABLE_ALGO 6        // AES256, BLOWFISH, CAMELLIA256, CAST5, SERPENT256, TWOFISH
#define AVAILABLE_ALGO_MODE 2   // CBC, CTR

typedef struct encrypt_file_widgets_t {
    GtkWidget *main_window;
    GtkWidget *cancel_btn;
    GtkWidget *radio_button_algo[AVAILABLE_ALGO];
    GtkWidget *radio_button_algo_mode[AVAILABLE_ALGO_MODE];
    GtkWidget *header_bar_menu;
} EncryptWidgets;

typedef struct file_metadata_t {
    guint8 *iv;
    guint8 *salt;
    guint algo;         // from 0 to 5, the order is written above, near to #define AVAILABLE_ALGO
    guint algo_mode;    // 0 or 1, the order is written above, near to #define AVAILABLE_ALGO_MODE
} Metadata;

static void do_header_bar (GtkWidget *, gpointer);

static GtkWidget *create_popover (GtkWidget *, GtkPositionType, gpointer);

static GtkWidget *get_final_box_layout (EncryptWidgets *);


void
encrypt_file_cb (GtkWidget *btn __attribute__((__unused__)),
                 gpointer user_data)
{
    EncryptWidgets *encrypt_widgets = g_new0 (EncryptWidgets, 1);
    encrypt_widgets->main_window = (GtkWidget *) user_data;

    gchar *filename = choose_file (encrypt_widgets->main_window);

    GtkWidget *dialog = create_dialog (encrypt_widgets->main_window, "enc_dialog", NULL);
    encrypt_widgets->cancel_btn = gtk_dialog_add_button (GTK_DIALOG (dialog), "Cancel", GTK_RESPONSE_CANCEL);
    gtk_widget_set_margin_top (encrypt_widgets->cancel_btn, 10);
    gtk_widget_set_size_request (dialog, 600, -1);

    do_header_bar (dialog, encrypt_widgets);

    GtkWidget *content_area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));

    // TODO: complete me
    GtkWidget *pwd1 = gtk_entry_new ();
    GtkWidget *pwd2 = gtk_entry_new ();
    gtk_entry_set_placeholder_text (GTK_ENTRY (pwd1), "Type password...");
    gtk_entry_set_placeholder_text (GTK_ENTRY (pwd2), "Retype password...");
    gtk_entry_set_visibility (GTK_ENTRY (pwd1), FALSE);
    gtk_entry_set_visibility (GTK_ENTRY (pwd2), FALSE);
    gtk_widget_set_hexpand (pwd1, TRUE);
    gtk_widget_set_hexpand (pwd2, TRUE);

    GtkWidget *grid = gtk_grid_new ();
    gtk_grid_attach (GTK_GRID (grid), pwd1, 0, 0, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), pwd2, 0, 1, 2, 1);

    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);

    gtk_container_add (GTK_CONTAINER (content_area), grid);

    gtk_widget_show_all (dialog);

    gint result = gtk_dialog_run (GTK_DIALOG (dialog));
    switch (result) {
        case GTK_RESPONSE_CANCEL:
            gtk_widget_destroy (dialog);
            multiple_free (2, (gpointer *) &encrypt_widgets, (gpointer *) &filename);
            break;
        default:
            break;
    }
}


static void
do_header_bar (GtkWidget *dialog, gpointer user_data)
{
    EncryptWidgets *encrypt_widgets = user_data;
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
    g_signal_connect_swapped (dialog, "button-press-event", G_CALLBACK (toggle_active_cb),
                              encrypt_widgets->header_bar_menu);

    gtk_header_bar_pack_start (GTK_HEADER_BAR (header_bar), GTK_WIDGET (encrypt_widgets->header_bar_menu));
}


static GtkWidget *
create_popover (GtkWidget *parent, GtkPositionType pos, gpointer user_data)
{
    EncryptWidgets *encrypt_widgets = user_data;

    const gchar *algo[] = {"AES256", "BLOWFISH", "CAMELLIA256", "CAST5", "SERPENT256", "TWOFISH"};
    const gchar *algo_type[] = {"CBC", "CTR"};

    GtkWidget *popover = gtk_popover_new (parent);
    gtk_popover_set_position (GTK_POPOVER (popover), pos);

    gint i, j;
    encrypt_widgets->radio_button_algo[0] = gtk_radio_button_new_with_label_from_widget (NULL, algo[0]);
    for (i = 1, j = 1; i < AVAILABLE_ALGO; i++, j++) {
        encrypt_widgets->radio_button_algo[i] = gtk_radio_button_new_with_label_from_widget(
                GTK_RADIO_BUTTON (encrypt_widgets->radio_button_algo[0]), algo[j]);
    }

    encrypt_widgets->radio_button_algo_mode[0] = gtk_radio_button_new_with_label_from_widget (NULL, algo_type[0]);
    encrypt_widgets->radio_button_algo_mode[1] = gtk_radio_button_new_with_label_from_widget (
            GTK_RADIO_BUTTON (encrypt_widgets->radio_button_algo_mode[0]), algo_type[1]);

    for (i = 0; i < AVAILABLE_ALGO; i++) {
        gtk_widget_set_name (encrypt_widgets->radio_button_algo[i], algo[i]);
    }

    for (i = 0; i < AVAILABLE_ALGO_MODE; i++) {
        gtk_widget_set_name (encrypt_widgets->radio_button_algo_mode[i], algo_type[i]);
    }

    GtkWidget *final_box = get_final_box_layout (encrypt_widgets);

    for (i = 0; i < AVAILABLE_ALGO; i++) {
        g_signal_connect_swapped (encrypt_widgets->radio_button_algo[i], "clicked", G_CALLBACK (toggle_active_cb),
                                  encrypt_widgets->header_bar_menu);
    }

    for (i = 0; i < AVAILABLE_ALGO_MODE; i++) {
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


static GtkWidget *
get_final_box_layout (EncryptWidgets *encrypt_widgets)
{
    const gchar *label_data[] = {"Cipher", "Mode"};

    gint num_of_vboxes = 6;
    gint num_of_hboxes = 2;

    GtkWidget *v_box[num_of_vboxes];
    GtkWidget *h_box[num_of_hboxes];

    gint i;
    for (i = 0; i < num_of_vboxes; i++) {
        v_box[i] = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
    }

    for (i = 0; i < num_of_hboxes; i++) {
        h_box[i] = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
    }

    GtkWidget *label[2];
    label[0] = gtk_label_new (label_data[0]);
    label[1] = gtk_label_new (label_data[1]);

    GtkWidget *v_line[2];
    v_line[0] = gtk_separator_new (GTK_ORIENTATION_VERTICAL);
    v_line[1] = gtk_separator_new (GTK_ORIENTATION_VERTICAL);

    GtkWidget *h_line[3];
    h_line[0] = gtk_separator_new (GTK_ORIENTATION_HORIZONTAL);
    h_line[1] = gtk_separator_new (GTK_ORIENTATION_HORIZONTAL);

    // Cipher
    // ------
    gtk_box_pack_start (GTK_BOX (v_box[0]), label[0], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (v_box[0]), h_line[0], FALSE, TRUE, 0);

    // Algo
    gtk_box_pack_start (GTK_BOX (v_box[1]), encrypt_widgets->radio_button_algo[0], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (v_box[1]), encrypt_widgets->radio_button_algo[1], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (v_box[1]), encrypt_widgets->radio_button_algo[2], FALSE, TRUE, 0);

    // Algo
    gtk_box_pack_start (GTK_BOX (v_box[2]), encrypt_widgets->radio_button_algo[3], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (v_box[2]), encrypt_widgets->radio_button_algo[4], FALSE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (v_box[2]), encrypt_widgets->radio_button_algo[5], FALSE, TRUE, 0);

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