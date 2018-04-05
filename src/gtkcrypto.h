#pragma once

#define PARTIAL_PATH_TO_UI_FILE "share/gtkcrypto/widgets.ui"

void        show_message_dialog             (GtkWidget *parent, const gchar *message, GtkMessageType);

GSList     *choose_file                     (GtkWidget *parent, const gchar *title, gboolean select_multiple);

gchar      *get_filename_from_list          (GSList *list);

gchar      *get_file_hash                   (const gchar *file_path, gint hash_algo, gint digest_size);

goffset     get_file_size                   (const gchar *file_path);

GtkWidget  *create_spinner                  (void);

void        start_spinner                   (GtkWidget *spinner);

void        stop_spinner                    (GtkWidget *spinner);

void        change_widgets_sensitivity      (gint number_of_widgets, gboolean value, GtkWidget **widget, ...);

GtkBuilder *get_builder_from_path           (const gchar *partial_path);