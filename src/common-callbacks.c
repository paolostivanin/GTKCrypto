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


void
copy_to_clipboard_cb (GtkEntry *entry,
                      GtkEntryIconPosition icon_pos  __attribute__((__unused__)),
                      GdkEvent *event __attribute__((__unused__)),
                      gpointer user_data __attribute__((__unused__)))
{
    gtk_editable_select_region (GTK_EDITABLE (entry), 0, -1);
    gtk_editable_copy_clipboard (GTK_EDITABLE (entry));
    gtk_editable_set_position (GTK_EDITABLE (entry), 0);
}