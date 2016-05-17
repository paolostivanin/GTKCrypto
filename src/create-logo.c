#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include "gtkcrypto.h"


GdkPixbuf *
create_logo (gboolean is_about_dialog)
{
    GError *err = NULL;
    GdkPixbuf *logo;

    const gchar *my_icon = "/usr/share/pixmaps/gtkcrypto.png";

    if (!is_about_dialog)
        logo = gdk_pixbuf_new_from_file (my_icon, &err);
    else
        logo = gdk_pixbuf_new_from_file_at_size (my_icon, 64, 64, &err);

    if (err != NULL)
        show_message_dialog (NULL, err->message, GTK_MESSAGE_ERROR);

    return logo;
}