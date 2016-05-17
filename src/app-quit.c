#include <gtk/gtk.h>

void
quit (GSimpleAction __attribute__((__unused__)) *action,
      GVariant __attribute__((__unused__)) *parameter,
      gpointer user_data)
{
    GtkApplication *app = user_data;

    g_assert (GTK_APPLICATION (app));

    g_application_quit (G_APPLICATION (app));
}