#pragma once

void show_message_dialog (GtkWidget *parent, const gchar *message, GtkMessageType);

gchar *choose_file (GtkWidget *parent, const gchar *title);

void multiple_free (gint, gpointer *, ...);

void multiple_gcry_free (gint, gpointer *, ...);

void multiple_unref (gint, gpointer *, ...);

gchar *get_file_hash (const gchar *file_path, gint hash_algo, gint digest_size);

goffset get_file_size (const gchar *file_path);

GtkWidget *create_spinner (void);

void start_spinner (GtkWidget *spinner);

void stop_spinner (GtkWidget *spinner);

void change_widgets_sensitivity (gint number_of_widgets, gboolean value, GtkWidget **widget, ...);

gboolean file_has_extension (const gchar *file_path, const gchar *ext);
