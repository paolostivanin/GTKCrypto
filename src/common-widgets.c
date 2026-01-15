#include <gtk/gtk.h>


GtkWidget *
create_dialog (GtkWidget    *main_window,
               const gchar  *widget_name,
               const gchar  *title)
{
    static GtkWidget *dialog = NULL;
    GtkWidget *outer_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *content_area = gtk_box_new (GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *action_area = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);

    dialog = gtk_window_new ();
    gtk_widget_set_name (dialog, widget_name);
    gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);
    if (main_window != NULL) {
        gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (main_window));
    }
    gtk_window_set_destroy_with_parent (GTK_WINDOW (dialog), TRUE);
    if (title != NULL) {
        gtk_window_set_title (GTK_WINDOW (dialog), title);
    }

    gtk_widget_set_margin_top (outer_box, 10);
    gtk_widget_set_margin_bottom (outer_box, 10);
    gtk_widget_set_margin_start (outer_box, 10);
    gtk_widget_set_margin_end (outer_box, 10);
    gtk_widget_set_halign (action_area, GTK_ALIGN_END);

    gtk_box_append (GTK_BOX (outer_box), content_area);
    gtk_box_append (GTK_BOX (outer_box), action_area);
    gtk_window_set_child (GTK_WINDOW (dialog), outer_box);

    g_object_set_data (G_OBJECT (dialog), "content-area", content_area);
    g_object_set_data (G_OBJECT (dialog), "action-area", action_area);

    return dialog;
}


GtkWidget *
create_header_bar (GtkWidget    *dialog,
                   const gchar  *title)
{
    static GtkWidget *header_bar = NULL;
    header_bar = gtk_header_bar_new();
    gtk_header_bar_set_show_title_buttons (GTK_HEADER_BAR (header_bar), FALSE);
    if (title != NULL) {
        GtkWidget *title_label = gtk_label_new (title);
        gtk_header_bar_set_title_widget (GTK_HEADER_BAR (header_bar), title_label);
    }
    gtk_window_set_titlebar (GTK_WINDOW (dialog), header_bar);

    return header_bar;
}

GtkWidget *
get_dialog_content_area (GtkWidget *dialog)
{
    return g_object_get_data (G_OBJECT (dialog), "content-area");
}

GtkWidget *
get_dialog_action_area (GtkWidget *dialog)
{
    return g_object_get_data (G_OBJECT (dialog), "action-area");
}


void
set_label_message (GtkWidget    *message_label,
                   const gchar  *message)
{
    gtk_label_set_markup (GTK_LABEL (message_label), message);
}
