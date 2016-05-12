#include <gtk/gtk.h>
#include <glib.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include "gtkcrypto.h"
#include "main.h"


GdkPixbuf *create_logo(gboolean is_about) {
    GError *err = NULL;
    GdkPixbuf *logo;

    const gchar *my_icon = "/usr/share/pixmaps/gtkcrypto.png";

    if (!is_about)
        logo = gdk_pixbuf_new_from_file(my_icon, &err);
    else
        logo = gdk_pixbuf_new_from_file_at_size(my_icon, 64, 64, &err);

    if (err != NULL)
        g_printerr("%s\n", err->message);

    return logo;
}
