#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED

#define NUM_OF_BUTTONS 6
#define NUM_OF_FRAMES 2
#define NUM_OF_BOXES 2
#define NUM_OF_HASH 10

#define HEADERBAR_BUF 22 /* buffer for the headerbar's title */

#include <glib.h>
#include <gtk/gtk.h>


GdkPixbuf *create_logo (gboolean);
GtkWidget *do_mainwin (GtkApplication *);
GtkWidget *create_popover (GtkWidget *, GtkPositionType, struct main_vars *);

gpointer crypt_file (gpointer);

void text_dialog (GtkWidget *, gpointer);

void compute_md5 (GtkWidget *, gpointer);
void compute_gost94 (GtkWidget *, gpointer);
void compute_sha1 (GtkWidget *, gpointer);
void compute_sha2 (GtkWidget *, gpointer);
void compute_sha3 (GtkWidget *, gpointer);
void compute_whirlpool (GtkWidget *, gpointer);

#endif
