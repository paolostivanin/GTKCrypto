#include <gtk/gtk.h>
#include <stdarg.h>


void set_css (const gchar *path, gint argc, GtkWidget **widget, ...)
{
    GError *err = NULL;
    gint i;

    GtkCssProvider *css = gtk_css_provider_new ();
    gtk_css_provider_load_from_path (css, path, &err);
    if (err != NULL) {
        g_printerr ("%s\n", err->message);
    }
    else {
        i = 0;
        va_list ptr;
        va_start (ptr, widget);
        while (i < argc) {
            gtk_style_context_add_provider(gtk_widget_get_style_context(*widget), GTK_STYLE_PROVIDER (css),
                                           GTK_STYLE_PROVIDER_PRIORITY_USER);
            widget = va_arg (ptr, GtkWidget **);
            i++;
        }
        va_end (ptr);
        g_object_unref (css);
    }
}