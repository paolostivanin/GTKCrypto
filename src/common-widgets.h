#pragma once

#include <gtk/gtk.h>

G_BEGIN_DECLS

GtkWidget *create_header_bar (GtkWidget   *dialog,
                              const gchar *title);

GtkWidget *create_dialog     (GtkWidget   *main_window,
                              const gchar *widget_name,
                              const gchar *title);

GtkWidget *get_dialog_content_area (GtkWidget *dialog);

GtkWidget *get_dialog_action_area  (GtkWidget *dialog);

void       set_label_message (GtkWidget   *message_label,
                              const gchar *message);

G_END_DECLS
