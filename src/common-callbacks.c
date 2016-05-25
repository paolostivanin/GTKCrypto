#include <gtk/gtk.h>
#include "common-callbacks.h"

void
toggle_changed_cb (GtkToggleButton *button, gpointer user_data)
{
    GtkWidget *popover = user_data;
    gtk_widget_set_visible (popover, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button)));
}


void
toggle_active_cb (gpointer user_data)
{
    GtkToggleButton *menu = user_data;
    if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (menu))) {
            gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (menu), FALSE);
    }
}
