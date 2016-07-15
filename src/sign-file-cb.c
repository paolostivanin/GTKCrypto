#include <gtk/gtk.h>
#include "common-widgets.h"
#include "gtkcrypto.h"
#include "gpgme-misc.h"


typedef struct sign_file_widgets_t {
    GtkWidget *main_window;
    GtkWidget *dialog;
    GtkWidget *cancel_btn;
    GtkWidget *ok_btn;
    GtkWidget *spinner;
    GtkWidget *message_label;
    gchar *filename;
} SignFileWidgets;


void
sign_file_cb (GtkWidget *btn __attribute__((__unused__)),
              gpointer user_data)
{
    SignFileWidgets *sign_file_widgets = g_new0 (SignFileWidgets, 1);

    sign_file_widgets->main_window = user_data;
    sign_file_widgets->filename = choose_file (sign_file_widgets->main_window);

    sign_file_widgets->dialog = create_dialog (sign_file_widgets->main_window, "sign_fl_diag", "Select GPG key");
    sign_file_widgets->cancel_btn = gtk_button_new_with_label ("Cancel");
    sign_file_widgets->ok_btn = gtk_button_new_with_label ("OK");
    gtk_widget_set_size_request (sign_file_widgets->dialog, 800, -1);

    sign_file_widgets->message_label = gtk_label_new ("");

    sign_file_widgets->spinner = create_spinner ();

    GSList *gpg_keys = get_available_keys ();

    GtkWidget *combo_box = gtk_combo_box_text_new ();

    gint i;
    gchar *str;
    GSList *to_free = NULL;
    for (i = 0; i < g_slist_length (gpg_keys); i++) {
        if (g_utf8_strlen (((KeyInfo *) (gpg_keys->data))->name, -1) +
            g_utf8_strlen (((KeyInfo *) (gpg_keys->data))->email, -1) > 128) {
                str = g_strconcat ("Name and email too long. Key ID: ", ((KeyInfo *) (gpg_keys->data))->key_id, NULL);
        }
        else {
            str = g_strconcat (((KeyInfo *) (gpg_keys->data))->name, " <", ((KeyInfo *) (gpg_keys->data))->email, "> (",
                              ((KeyInfo *) (gpg_keys->data))->key_id, ")", NULL);
        }
        to_free = g_slist_append (to_free, g_strdup (str));
        g_free (str);
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box),
                                        (gchar *) g_slist_nth_data (to_free, g_slist_length (to_free) - 1));
    }

    GtkWidget *grid = gtk_grid_new ();

    g_slist_free_full (gpg_keys, g_free);
    g_slist_free_full (to_free, g_free);

    // TODO message dialog "signed for FPR user email"
    return;
}