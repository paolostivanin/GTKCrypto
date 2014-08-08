#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED

#include <glib.h>
#include <gtk/gtk.h>

GdkPixbuf *create_logo (gboolean);
GtkWidget *do_mainwin (GtkApplication *);
GtkWidget *create_popover (GtkWidget *, GtkPositionType, struct main_vars *);

gpointer crypt_file (gpointer);

void error_dialog (const gchar *);

gint check_pwd (GtkWidget *, GtkWidget *);

void text_dialog (GtkWidget *);

void compute_sha2 (GtkWidget *, struct hash_vars *);
void compute_sha3 (GtkWidget *, struct hash_vars *);
void compute_md5 (struct hash_vars *);
void compute_sha1 (struct hash_vars *);
void compute_gost94 (struct hash_vars *);
void compute_whirlpool (struct hash_vars *);


#endif
