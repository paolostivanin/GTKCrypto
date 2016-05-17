#include <gtk/gtk.h>
#include "main.h"

gint
main (gint argc, gchar **argv)
{
    GtkApplication *app;
    gint status;

    GdkPixbuf *logo = create_logo(FALSE);

    if (logo != NULL)
        gtk_window_set_default_icon(logo);

    app = gtk_application_new("org.gnome.gtkcrypto", G_APPLICATION_FLAGS_NONE);
    g_signal_connect (app, "startup", G_CALLBACK(startup), NULL);
    g_signal_connect (app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION (app), argc, argv);
    g_object_unref(app);

    return status;
}
