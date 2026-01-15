#include <gtk/gtk.h>
#include <gcrypt.h>
#include "main.h"
#include "gtkcrypto.h"

static GtkWidget *get_main_window (GtkBuilder *builder);


void
activate (GtkApplication *app,
          gpointer        user_data __attribute__((unused)))
{
    GtkBuilder *builder = get_builder_from_path (PARTIAL_PATH_TO_UI_FILE);
    if (builder == NULL) {
        return;
    }

    GtkWidget *main_window = get_main_window (builder);
    gtk_application_add_window (GTK_APPLICATION (app), GTK_WINDOW (main_window));

    if (!gcry_check_version (GCRYPT_MIN_VERSION)) {
        show_message_dialog (main_window, "The required version of GCrypt is 1.7.0 or greater.", GTK_MESSAGE_ERROR);
        return;
    }

    if (gcry_control (GCRYCTL_INIT_SECMEM, SECURE_MEMORY_POOL_SIZE, 0)) {
        show_message_dialog (main_window, "Couldn't initialize secure memory.\n", GTK_MESSAGE_ERROR);
        g_application_quit (G_APPLICATION (app));
        return;
    }
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    g_signal_connect (GTK_WIDGET (gtk_builder_get_object (builder, "encfile_btn")), "clicked", G_CALLBACK (encrypt_files_cb), main_window);
    g_signal_connect (GTK_WIDGET (gtk_builder_get_object (builder, "decfile_btn")), "clicked", G_CALLBACK (decrypt_files_cb), main_window);
    g_signal_connect (GTK_WIDGET (gtk_builder_get_object (builder, "sigfile_btn")), "clicked", G_CALLBACK (sign_file_cb), main_window);
    g_signal_connect (GTK_WIDGET (gtk_builder_get_object (builder, "versig_btn")), "clicked", G_CALLBACK (verify_signature_cb), main_window);
    g_signal_connect (GTK_WIDGET (gtk_builder_get_object (builder, "enctxt_btn")), "clicked", G_CALLBACK (txt_cb), NULL);
    g_signal_connect (GTK_WIDGET (gtk_builder_get_object (builder, "dectxt_btn")), "clicked", G_CALLBACK (txt_cb), NULL);
    g_signal_connect (GTK_WIDGET (gtk_builder_get_object (builder, "chash_btn")), "clicked", G_CALLBACK (compute_hash_cb), main_window);
    g_signal_connect (GTK_WIDGET (gtk_builder_get_object (builder, "cmphash_btn")), "clicked", G_CALLBACK (compare_files_hash_cb), main_window);

    g_object_unref (builder);

    gtk_window_present (GTK_WINDOW (main_window));
}


static GtkWidget *
get_main_window (GtkBuilder *builder)
{
    GtkWidget *window = GTK_WIDGET (gtk_builder_get_object(builder, "mainwin"));

    gchar *header_bar_text = g_malloc0 (strlen (APP_NAME) + strlen (APP_VERSION) + 2);
    g_snprintf (header_bar_text, strlen (APP_NAME) +1 + strlen (APP_VERSION) + 1, "%s %s", APP_NAME, APP_VERSION);

    GtkWidget *header_bar = (GTK_WIDGET (gtk_builder_get_object(builder, "main_hb")));
    GtkWidget *title_label = gtk_label_new (header_bar_text);
    gtk_header_bar_set_title_widget (GTK_HEADER_BAR (header_bar), title_label);
    g_free (header_bar_text);

    return window;
}
