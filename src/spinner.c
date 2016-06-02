#include <gtk/gtk.h>
#include "gtkcrypto.h"


GtkWidget *
create_spinner ()
{
    return gtk_spinner_new();
}


void
start_spinner (GtkWidget *spinner)
{
    gtk_spinner_start (GTK_SPINNER (spinner));
}


void
stop_spinner (GtkWidget *spinner)
{
    gtk_spinner_stop (GTK_SPINNER (spinner));
}