#ifndef GTKCRYPTO_H_INCLUDED
#define GTKCRYPTO_H_INCLUDED

#include <gtk/gtk.h>

void show_message_dialog (GtkWidget *, const gchar *, GtkMessageType);

gchar *choose_file (GtkWidget *);

void multiple_free (gint, gpointer *, ...);

void set_css (const gchar *, gint, GtkWidget **, ...);

gchar *get_file_hash (const gchar *, gint, gint);

goffset get_file_size (const gchar *);

GtkWidget *create_spinner (void);

void start_spinner (GtkWidget *);

void stop_spinner (GtkWidget *);

#endif