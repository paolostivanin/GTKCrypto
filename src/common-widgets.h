#pragma once

#include <gtk/gtk.h>

G_BEGIN_DECLS

GtkWidget *create_header_bar (GtkWidget   *dialog,
                              const gchar *title);

GtkWidget *create_dialog     (GtkWidget   *main_window,
                              const gchar *widget_name,
                              const gchar *title);

void       set_label_message (GtkWidget   *message_label,
                              const gchar *message);

G_END_DECLS