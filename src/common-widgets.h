#pragma once

#include <gtk/gtk.h>

GtkWidget *create_header_bar (GtkWidget *, const gchar *);

GtkWidget *create_dialog (GtkWidget *, const gchar *, const gchar *);

void set_label_message (GtkWidget *message_label, const gchar *message);
