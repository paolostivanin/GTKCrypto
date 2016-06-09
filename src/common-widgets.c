#include <gtk/gtk.h>


GtkWidget *
create_dialog (GtkWidget *main_window, const gchar *widget_name, const gchar *title)
{
    static GtkWidget *dialog = NULL;
    dialog = gtk_dialog_new ();
    gtk_widget_set_name (dialog, widget_name);
    gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (main_window));
    gtk_window_set_destroy_with_parent (GTK_WINDOW (dialog), TRUE);

    if (title != NULL) {
        gtk_window_set_title (GTK_WINDOW (dialog), title);
    }

    return dialog;
}


GtkWidget *
create_header_bar (GtkWidget *dialog, const gchar *title)
{
    static GtkWidget *header_bar = NULL;
    header_bar = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button (GTK_HEADER_BAR (header_bar), FALSE);
    gtk_header_bar_set_title (GTK_HEADER_BAR (header_bar), title);
    gtk_header_bar_set_has_subtitle (GTK_HEADER_BAR (header_bar), FALSE);
    gtk_window_set_titlebar (GTK_WINDOW (dialog), header_bar);

    return header_bar;
}