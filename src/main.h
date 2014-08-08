#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED

#define NUM_OF_BUTTONS 6
#define NUM_OF_FRAMES 2
#define NUM_OF_BOXES 2
#define NUM_OF_HASH 8

#include <glib.h>
#include <gtk/gtk.h>

GdkPixbuf *create_logo (gboolean);
GtkWidget *do_mainwin (GtkApplication *);
GtkWidget *create_popover (GtkWidget *, GtkPositionType, struct main_vars *);

gpointer crypt_file (gpointer);

void text_dialog (GtkWidget *);

void compute_sha2 (GtkWidget *, struct hash_vars *);
void compute_sha3 (GtkWidget *, struct hash_vars *);
void compute_md5 (struct hash_vars *);
void compute_sha1 (struct hash_vars *);
void compute_gost94 (struct hash_vars *);
void compute_whirlpool (struct hash_vars *);


#endif
