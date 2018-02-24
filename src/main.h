#pragma once

#define APP_NAME                "GTKCrypto"
#define APP_VERSION             "1.0.0-beta"
#define GCRYPT_MIN_VERSION      "1.7.0"
#define SECURE_MEMORY_POOL_SIZE 32768


void        activate                (GtkApplication *app, gpointer user_data);

void        add_boxes_and_grid      (GtkWidget *main_window);

void        compare_files_hash_cb   (GtkWidget *button, gpointer user_data);

void        compute_hash_cb         (GtkWidget *button, gpointer user_data);

void        encrypt_files_cb        (GtkWidget *button, gpointer user_data);

void        decrypt_files_cb        (GtkWidget *button, gpointer user_data);

void        sign_file_cb            (GtkWidget *button, gpointer user_data);

void        verify_signature_cb     (GtkWidget *button, gpointer user_data);
