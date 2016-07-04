#ifndef CALLBACKS_H
#define CALLBACKS_H

void toggle_changed_cb (GtkToggleButton *, gpointer user_data);

void toggle_active_cb (gpointer user_data);

void copy_to_clipboard_cb (GtkEntry *, GtkEntryIconPosition, GdkEvent *, gpointer user_data);

#endif
