#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED

#include <gtk/gtk.h>

#define APP_NAME "GTKCrypto"
#define APP_VERSION "1.0.0"
#define GCRYPT_MIN_VERSION "1.7.0"

typedef struct widgets_t {
    GtkWidget *main_window;
} AppWidgets;

void startup (GtkApplication *, gpointer);

void activate (GtkApplication *, gpointer);

void quit (GSimpleAction *, GVariant *, gpointer);

void about (GSimpleAction *, GVariant *, gpointer);

GdkPixbuf *create_logo (gboolean);

GtkWidget *create_main_window (GtkApplication *);

void add_boxes_and_grid (AppWidgets *);

gchar *get_file_hash (gpointer);

#endif
