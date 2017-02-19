#include <gtk/gtk.h>
#include "main.h"

void
about (GSimpleAction __attribute__((__unused__)) *action,
       GVariant __attribute__((__unused__)) *parameter,
       gpointer __attribute__((__unused__)) data)
{
    const gchar *authors[] = {
            "Paolo Stivanin <info@paolostivanin.com>",
            NULL,
    };

    GtkWidget *a_dialog = gtk_about_dialog_new ();
    gtk_about_dialog_set_program_name (GTK_ABOUT_DIALOG (a_dialog), "GTKCrypto");

    GdkPixbuf *logo = create_logo (TRUE);
    if (logo != NULL)
        gtk_about_dialog_set_logo(GTK_ABOUT_DIALOG (a_dialog), logo);

    gtk_about_dialog_set_version (GTK_ABOUT_DIALOG (a_dialog), APP_VERSION);

    gtk_about_dialog_set_copyright (GTK_ABOUT_DIALOG (a_dialog), "Copyright (C) 2017");

    gtk_about_dialog_set_comments (GTK_ABOUT_DIALOG (a_dialog),
                                  "Encrypt and decrypt files using different cipher algo and different cipher mode or "
                                          "compute their hash using different algo");

    gtk_about_dialog_set_license_type (GTK_ABOUT_DIALOG (a_dialog), GTK_LICENSE_GPL_3_0);

    gtk_about_dialog_set_website (GTK_ABOUT_DIALOG (a_dialog), "https://paolostivanin.com");

    gtk_about_dialog_set_authors (GTK_ABOUT_DIALOG (a_dialog), authors);

    gtk_dialog_run (GTK_DIALOG (a_dialog));

    gtk_widget_destroy (a_dialog);
}