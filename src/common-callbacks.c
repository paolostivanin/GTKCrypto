#include <gtk/gtk.h>
#include "common-callbacks.h"

void
copy_to_clipboard_cb (GtkEntry              *entry,
                      GtkEntryIconPosition   icon_pos   __attribute__((unused)),
                      GdkEvent              *event      __attribute__((unused)),
                      gpointer               user_data  __attribute__((unused)))
{
    const gchar *text = gtk_editable_get_text (GTK_EDITABLE (entry));
    GdkClipboard *clipboard = gtk_widget_get_clipboard (GTK_WIDGET (entry));

    if (text != NULL) {
        gdk_clipboard_set_text (clipboard, text);
    }

    gtk_editable_select_region (GTK_EDITABLE (entry), 0, -1);
    gtk_editable_set_position (GTK_EDITABLE (entry), 0);
}
