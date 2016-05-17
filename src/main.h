#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED

#include <gtk/gtk.h>

#define APP_NAME "GTKCrypto"
#define APP_VERSION "1.0.0"

void startup (GtkApplication *, gpointer);

void activate (GtkApplication *, gpointer);

GdkPixbuf *create_logo(gboolean);

GtkWidget *create_main_window (GtkApplication *);

#endif //GTKCRYPTO_MAIN_H
