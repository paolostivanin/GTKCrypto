#include <gtk/gtk.h>
#include <gcrypt.h>
#include "main.h"
#include "gtkcrypto.h"

static GtkWidget *create_main_window (GtkApplication *app);


void
activate (GtkApplication *app,
          gpointer        user_data __attribute__((unused)))
{
    GtkWidget *main_window = create_main_window (app);
    gtk_application_add_window (GTK_APPLICATION (app), GTK_WINDOW (main_window));

    if (!gcry_check_version (GCRYPT_MIN_VERSION)) {
        show_message_dialog (main_window, "The required version of GCrypt is 1.7.0 or greater.", GTK_MESSAGE_ERROR);
        return;
    }

    gcry_control (GCRYCTL_INIT_SECMEM, SECURE_MEMORY_POOL_SIZE, 0);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    add_boxes_and_grid (main_window);

    gtk_widget_show_all (main_window);
}


static GtkWidget *
create_main_window (GtkApplication *app)
{
    GtkWidget *window = gtk_application_window_new (app);
    gtk_window_set_position (GTK_WINDOW (window), GTK_WIN_POS_CENTER);
    gtk_window_set_resizable (GTK_WINDOW (window), FALSE);

    gtk_window_set_icon_name (GTK_WINDOW (window), "gtkcrypto");

    gtk_container_set_border_width (GTK_CONTAINER (window), 10);

    gtk_widget_set_size_request (GTK_WIDGET (window), 475, 360);

    gchar *header_bar_text = g_malloc (strlen (APP_NAME ) + 1 + strlen (APP_VERSION) + 1);
    g_snprintf (header_bar_text, strlen (APP_NAME) + 1 + strlen (APP_VERSION) + 1,
                "%s %s", APP_NAME, APP_VERSION);
    header_bar_text[strlen(header_bar_text)] = '\0';

    GtkWidget *header_bar = gtk_header_bar_new ();
    gtk_header_bar_set_show_close_button (GTK_HEADER_BAR (header_bar), TRUE);
    gtk_header_bar_set_title (GTK_HEADER_BAR (header_bar), header_bar_text);
    gtk_header_bar_set_has_subtitle (GTK_HEADER_BAR (header_bar), FALSE);

    GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_style_context_add_class (gtk_widget_get_style_context (box), "linked");

    gtk_window_set_titlebar (GTK_WINDOW (window), header_bar);

    return window;
}