#include <gtk/gtk.h>
#include <gcrypt.h>
#include "main.h"
#include "gtkcrypto.h"

void
activate (GtkApplication *app,
          gpointer __attribute__((__unused__)) data)
{
    AppWidgets *widgets = g_new0 (AppWidgets, 1);

    widgets->main_window = create_main_window (app);
    gtk_application_add_window (GTK_APPLICATION (app), GTK_WINDOW (widgets->main_window));

    if (!gcry_check_version (GCRYPT_MIN_VERSION)) {
        show_message_dialog (widgets->main_window, "The required version of GCrypt is 1.7.0 or greater.", GTK_MESSAGE_ERROR);
        return;
    }

    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    add_boxes_and_grid (widgets);

    gtk_widget_show_all(widgets->main_window);
}