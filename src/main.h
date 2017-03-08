#pragma once

#define APP_NAME "GTKCrypto"
#define APP_VERSION "1.0-beta2"
#define GCRYPT_MIN_VERSION "1.7.0"

typedef struct widgets_t {
    GtkWidget *main_window;
} AppWidgets;

void startup (GtkApplication *app, gpointer);

void activate (GtkApplication *app, gpointer);

void quit (GSimpleAction *, GVariant *, gpointer);

void about (GSimpleAction *, GVariant *, gpointer);

GdkPixbuf *create_logo (gboolean);

GtkWidget *create_main_window (GtkApplication *app);

void add_boxes_and_grid (AppWidgets *);

void compare_files_hash_cb (GtkWidget *, gpointer);

void compute_hash_cb (GtkWidget *, gpointer);

void encrypt_file_cb (GtkWidget *, gpointer);

void decrypt_file_cb (GtkWidget *, gpointer);

void sign_file_cb (GtkWidget *, gpointer);

void verify_signature_cb (GtkWidget *, gpointer);
