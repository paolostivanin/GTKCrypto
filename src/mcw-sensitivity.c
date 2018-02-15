#include <gtk/gtk.h>

void
change_widgets_sensitivity (gint argc, gboolean value, GtkWidget **widget, ...)
{
    gint i = 0;
    va_list ptr;
    va_start (ptr, widget);
    while (i < argc) {
        if (gtk_widget_get_sensitive (*widget) != value) {
            gtk_widget_set_sensitive (*widget, value);
        }
        widget = va_arg (ptr, GtkWidget **);
        i++;
    }
    va_end (ptr);
}