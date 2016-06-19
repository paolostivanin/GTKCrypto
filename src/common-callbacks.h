#ifndef CALLBACKS_H
#define CALLBACKS_H

void toggle_changed_cb (GtkToggleButton *, gpointer);

void toggle_active_cb (gpointer);

void copy_to_clipboard_cb (GtkEntry *, GtkEntryIconPosition, GdkEvent *, gpointer);

#endif
