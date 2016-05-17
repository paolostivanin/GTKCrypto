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
    gtk_about_dialog_set_copyright (GTK_ABOUT_DIALOG (a_dialog), "Copyright (C) 2016");
    gtk_about_dialog_set_comments (GTK_ABOUT_DIALOG (a_dialog),
                                  "Encrypt and decrypt files using different cipher algo and different cipher mode or "
                                          "compute their hash using different algo");
    gtk_about_dialog_set_license (GTK_ABOUT_DIALOG(a_dialog),
                                 "This program is free software: you can redistribute it and/or modify it under the "
                                         "terms of the GNU General Public License as published by the "
                                         "Free Software Foundation, either version 3 of the License, or (at your option)"
                                         " any later version.\n"
                                         "This program is distributed in the hope that it will be useful, but "
                                         "WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY"
                                         "or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License "
                                         "for more details.\n"
                                         "You should have received a copy of the GNU General Public License "
                                         "along with this program.\n"
                                         "If not, see http://www.gnu.org/licenses\n"
                                         "GTKCrypto is Copyright (C) 2016 by Paolo Stivanin.\n");
    gtk_about_dialog_set_wrap_license (GTK_ABOUT_DIALOG (a_dialog), TRUE);
    gtk_about_dialog_set_website (GTK_ABOUT_DIALOG (a_dialog), "https://paolostivanin.com");
    gtk_about_dialog_set_authors (GTK_ABOUT_DIALOG (a_dialog), authors);
    gtk_dialog_run (GTK_DIALOG (a_dialog));
    gtk_widget_destroy (a_dialog);
}