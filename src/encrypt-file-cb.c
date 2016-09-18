#include <gtk/gtk.h>
#include "gtkcrypto.h"
#include "common-widgets.h"
#include "common-callbacks.h"
#include "crypt-common.h"
#include "encrypt-file-cb.h"

typedef struct encrypt_file_widgets_t {
    GtkWidget *main_window;
    GtkWidget *dialog;
    GtkWidget *entry_pwd;
    GtkWidget *entry_pwd_retype;
    GtkWidget *ck_btn_delete;
    GtkWidget *cancel_btn;
    GtkWidget *ok_btn;
    GtkWidget *radio_button_algo[AVAILABLE_ALGO];
    GtkWidget *radio_button_algo_mode[AVAILABLE_ALGO_MODE];
    GtkWidget *header_bar_menu;
    GtkWidget *spinner;
    GtkWidget *message_label;
    gchar *filename;
    GThread *enc_thread;
} EncryptWidgets;

typedef struct enc_thread_data_t {
    GtkWidget *dialog;
    GtkWidget *spinner;
    GtkWidget *message_label;
    const gchar *algo_btn_name;
    const gchar *algo_mode_btn_name;
    const gchar *filename;
    const gchar *pwd;
    gboolean delete_file;
} ThreadData;

static void entry_activated_cb (GtkWidget *, gpointer);

static void do_header_bar (GtkWidget *, gpointer);

static GtkWidget *create_popover (GtkWidget *, GtkPositionType, gpointer);

static GtkWidget *get_final_box_layout (EncryptWidgets *);

static gboolean check_pwd (GtkWidget *, GtkWidget *, GtkWidget *);

static void prepare_encryption (const gchar *, const gchar *, EncryptWidgets *);

static gpointer exec_thread (gpointer);

static void cancel_clicked_cb (GtkWidget *, gpointer);


void
encrypt_file_cb (GtkWidget *btn __attribute__((__unused__)),
                 gpointer user_data)
{
    EncryptWidgets *encrypt_widgets = g_new0 (EncryptWidgets, 1);

    encrypt_widgets->main_window = (GtkWidget *) user_data;
    encrypt_widgets->enc_thread = NULL;

    encrypt_widgets->filename = choose_file (encrypt_widgets->main_window, "Pick file to encrypt");

    encrypt_widgets->dialog = create_dialog (encrypt_widgets->main_window, "enc_dialog", NULL);
    encrypt_widgets->cancel_btn = gtk_button_new_with_label ("Cancel");
    encrypt_widgets->ok_btn = gtk_button_new_with_label ("OK");
    gtk_widget_set_size_request (encrypt_widgets->dialog, 600, -1);

    do_header_bar (encrypt_widgets->dialog, encrypt_widgets);

    encrypt_widgets->entry_pwd = gtk_entry_new ();
    encrypt_widgets->entry_pwd_retype = gtk_entry_new ();
    gtk_entry_set_placeholder_text (GTK_ENTRY (encrypt_widgets->entry_pwd), "Type password...");
    gtk_entry_set_placeholder_text (GTK_ENTRY (encrypt_widgets->entry_pwd_retype), "Retype password...");
    gtk_entry_set_visibility (GTK_ENTRY (encrypt_widgets->entry_pwd), FALSE);
    gtk_entry_set_visibility (GTK_ENTRY (encrypt_widgets->entry_pwd_retype), FALSE);
    gtk_widget_set_hexpand (encrypt_widgets->entry_pwd, TRUE);
    gtk_widget_set_hexpand (encrypt_widgets->entry_pwd_retype, TRUE);

    encrypt_widgets->ck_btn_delete = gtk_check_button_new_with_label ("Securely delete original file");

    encrypt_widgets->message_label = gtk_label_new ("");

    encrypt_widgets->spinner = create_spinner ();

    GtkWidget *grid = gtk_grid_new ();
    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_attach (GTK_GRID (grid), encrypt_widgets->entry_pwd, 0, 0, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), encrypt_widgets->entry_pwd_retype, 0, 1, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), encrypt_widgets->ck_btn_delete, 0, 2, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), encrypt_widgets->message_label, 0, 3, 2, 1);
    gtk_grid_attach_next_to (GTK_GRID (grid), encrypt_widgets->spinner, encrypt_widgets->message_label, GTK_POS_RIGHT, 1, 1);

    GtkWidget *hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_end (GTK_BOX(hbox), encrypt_widgets->ok_btn, TRUE, TRUE, 0);
    gtk_box_pack_end (GTK_BOX(hbox), encrypt_widgets->cancel_btn, TRUE, TRUE, 0);
    gtk_grid_attach (GTK_GRID (grid), hbox, 1, 4, 1, 1);

    gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (GTK_DIALOG (encrypt_widgets->dialog))), grid);

    gtk_widget_show_all (encrypt_widgets->dialog);

    gtk_widget_hide (encrypt_widgets->spinner);

    g_signal_connect (encrypt_widgets->entry_pwd_retype, "activate", G_CALLBACK (entry_activated_cb), encrypt_widgets);
    g_signal_connect (encrypt_widgets->ok_btn, "clicked", G_CALLBACK (entry_activated_cb), encrypt_widgets);
    g_signal_connect (encrypt_widgets->cancel_btn, "clicked", G_CALLBACK (cancel_clicked_cb), encrypt_widgets);

    gint result = gtk_dialog_run (GTK_DIALOG (encrypt_widgets->dialog));
    switch (result) {
        case GTK_RESPONSE_DELETE_EVENT:
            if (encrypt_widgets->enc_thread != NULL) {
                gpointer msg = g_thread_join (encrypt_widgets->enc_thread);
                if (msg != NULL) {
                    show_message_dialog (encrypt_widgets->main_window, (gchar *) msg, GTK_MESSAGE_ERROR);
                    g_free (msg);
                }
            }
            gtk_widget_destroy (encrypt_widgets->dialog);
            multiple_free (2, (gpointer) &encrypt_widgets->filename, (gpointer) &encrypt_widgets);
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


static GtkWidget *
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


static void
entry_activated_cb (GtkWidget *entry __attribute__((__unused__)),
                    gpointer user_data)
{
    EncryptWidgets *encrypt_widgets = user_data;

    if (!check_pwd (encrypt_widgets->main_window, encrypt_widgets->entry_pwd, encrypt_widgets->entry_pwd_retype)) {
        return;
    }
    else {
        for (gint i = 0; i < AVAILABLE_ALGO; i++) {
            if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (encrypt_widgets->radio_button_algo[i]))) {
                break;
            }
        }
        for (gint j = 0; j < AVAILABLE_ALGO_MODE; j++) {
            if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (encrypt_widgets->radio_button_algo_mode[j]))) {
                break;
            }
        }
        prepare_encryption (gtk_widget_get_name (encrypt_widgets->radio_button_algo[i]),
                            gtk_widget_get_name (encrypt_widgets->radio_button_algo_mode[j]),
                            encrypt_widgets);
    }
}


static gboolean
check_pwd (GtkWidget *main_window, GtkWidget *entry, GtkWidget *retype_entry)
{
    const gchar *text_entry = gtk_entry_get_text (GTK_ENTRY (entry));
    const gchar *text_retype_entry = gtk_entry_get_text (GTK_ENTRY (retype_entry));

    gint cmp_retval = g_strcmp0 (text_entry, text_retype_entry);

    if (cmp_retval != 0) {
        show_message_dialog (main_window,
                             "The passwords are different, try again...",
                             GTK_MESSAGE_ERROR);
        return FALSE;
    }
    else if (cmp_retval == 0 && g_utf8_strlen (text_entry, -1) < 8) {
        show_message_dialog (main_window,
                             "Password is too short (< 8 chars). Please choose a stronger password.",
                             GTK_MESSAGE_ERROR);
        return FALSE;
    }
    else {
        return TRUE;
    }
}


static void
prepare_encryption (const gchar *algo, const gchar *algo_mode, EncryptWidgets *data)
{
    ThreadData *thread_data = g_new0 (ThreadData, 1);

    thread_data->dialog = data->dialog;
    thread_data->spinner = data->spinner;
    thread_data->message_label = data->message_label;
    thread_data->algo_btn_name = algo;
    thread_data->algo_mode_btn_name = algo_mode;
    thread_data->filename = data->filename;
    thread_data->pwd = gtk_entry_get_text (GTK_ENTRY (data->entry_pwd));

    if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data->ck_btn_delete))) {
        thread_data->delete_file = TRUE;
    }
    else {
        thread_data->delete_file = FALSE;
    }

    gtk_widget_show (thread_data->spinner);
    start_spinner (thread_data->spinner);

    change_widgets_sensitivity (5, FALSE, &data->ok_btn, &data->cancel_btn, &data->entry_pwd, &data->entry_pwd_retype, &data->ck_btn_delete);

    data->enc_thread = g_thread_new (NULL, exec_thread, thread_data);
}


static gpointer
exec_thread (gpointer user_data)
{
    ThreadData *data = user_data;

    gchar *basename = g_path_get_basename (data->filename);

    gchar *message = g_strconcat ("Encrypting <b>", basename, "</b>...", NULL);
    set_label_message (data->message_label, message);
    gpointer msg = encrypt_file (data->filename, data->pwd, data->algo_btn_name, data->algo_mode_btn_name);

    if (data->delete_file && msg == NULL) {
            message = g_strconcat ("Overwriting and deleting <b>", basename, "</b>...", NULL);
            set_label_message (data->message_label, "Deleting...");
            secure_file_delete (data->filename);
    }

    gtk_dialog_response (GTK_DIALOG (data->dialog), GTK_RESPONSE_DELETE_EVENT);

    multiple_free (3, (gpointer) &data, (gpointer) &basename, (gpointer) &message);

    g_thread_exit (msg);
}


static void
cancel_clicked_cb (GtkWidget *btn __attribute__((__unused__)),
                   gpointer user_data)
{
    EncryptWidgets *encrypt_widgets = user_data;

    gtk_widget_destroy (encrypt_widgets->dialog);

    multiple_free (2, (gpointer) &encrypt_widgets->filename, (gpointer) &encrypt_widgets);
}