#ifndef GTKCRYPTO_H_INCLUDED
#define GTKCRYPTO_H_INCLUDED

void show_message_dialog (GtkWidget *, const gchar *, GtkMessageType);

gchar *choose_file (GtkWidget *);

void multiple_free (gint, gpointer *, ...);

void set_css (const gchar *, gint, GtkWidget **, ...);

#endif