#pragma once

void toggle_changed_cb      (GtkToggleButton *toggle_btn, gpointer user_data);

void toggle_active_cb       (gpointer user_data);

void copy_to_clipboard_cb   (GtkEntry *entry, GtkEntryIconPosition, GdkEvent *event, gpointer user_data);
