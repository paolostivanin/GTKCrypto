#include <gtk/gtk.h>
#include "gtkcrypto.h"
#include "encrypt-cb-common.h"

void
encrypt_file_cb (GtkWidget *btn __attribute__((__unused__)),
                 gpointer   user_data)
{
    EncryptWidgets *encrypt_widgets = g_new0 (EncryptWidgets, 1);

    encrypt_widgets->main_window = (GtkWidget *) user_data;
    encrypt_widgets->enc_thread = NULL;

    encrypt_widgets->files_list = choose_file (encrypt_widgets->main_window, "Choose file(s) to encrypt", TRUE);
    if (encrypt_widgets->files_list == NULL) {
        g_free (encrypt_widgets);
        return;
    } else if (g_slist_length (encrypt_widgets->files_list) == 1) {
        encrypt_single_file_dialog (encrypt_widgets);
    } else {
        encrypt_multiple_files_dialog (encrypt_widgets);
    }
}