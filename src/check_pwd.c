#include <gtk/gtk.h>
#include <glib.h>
#include "gtkcrypto.h"


gint check_pwd(GtkWidget *first_pwd_entry, GtkWidget *second_pwd_entry) {
    const gchar *pw1 = gtk_entry_get_text(GTK_ENTRY (first_pwd_entry));
    const gchar *pw2 = gtk_entry_get_text(GTK_ENTRY (second_pwd_entry));

    if (g_strcmp0(pw1, pw2) != 0)
        return PASSWORD_MISMATCH;

    else if (g_utf8_strlen(pw1, -1) < 8)
        return PASSWORD_TOO_SHORT;

    else
        return 0;
}
