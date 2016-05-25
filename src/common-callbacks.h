#ifndef CALLBACKS_H
#define CALLBACKS_H

#include <gtk/gtk.h>

void compare_files_hash_cb (GtkWidget *, gpointer);

void compute_hash_cb (GtkWidget *, gpointer);

void toggle_changed_cb (GtkToggleButton *, gpointer);

void toggle_active_cb (gpointer);

#endif
