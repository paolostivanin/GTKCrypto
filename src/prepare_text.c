#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <libnotify/notify.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "polcrypt.h"

struct _widget{
	GtkTextBuffer *buffer;
	GtkTextBuffer *buffer_2;
};

struct _widget Widgets;

void on_button_clicked (GtkWidget *button __attribute__ ((unused)), struct _widget *Widgets){
	GtkTextIter start;
	GtkTextIter end;
	
	gchar *text;

	/* Obtain iters for the start and end of points of the buffer */
	gtk_text_buffer_get_start_iter (Widgets->buffer, &start);
	gtk_text_buffer_get_end_iter (Widgets->buffer, &end);

	/* Get the entire buffer text. */
	text = gtk_text_buffer_get_text (Widgets->buffer, &start, &end, FALSE);

	g_free (text);
}

gint prepare_text(){
	GtkWidget *window;
	GtkWidget *grid;
	GtkWidget *text_view;
	GtkWidget *button;
  
	window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title (GTK_WINDOW (window), "Insert Text");

	gtk_window_set_default_size (GTK_WINDOW (window), 200, 200);
	g_signal_connect (GTK_WINDOW(window), "destroy", G_CALLBACK (gtk_main_quit), NULL);

	grid = gtk_grid_new ();
	gtk_container_add (GTK_CONTAINER (window), grid);

	text_view = gtk_text_view_new ();
	button = gtk_button_new_with_label ("OK");
	
	gtk_grid_attach (GTK_GRID (grid), text_view, 0, 0, 4, 4);
	gtk_grid_attach (GTK_GRID (grid), button, 0, 5, 4, 1);
	
	g_object_set (text_view, "expand", TRUE, NULL);

	/* Obtaining the buffer associated with the widget. */
	Widgets.buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (text_view));

	/* Set the default buffer text. */ 
	gtk_text_buffer_set_text (Widgets.buffer, "Write here the text which will be encrypted", -1);
  
	g_signal_connect(button, "clicked", G_CALLBACK (on_button_clicked), &Widgets);
  
	gtk_widget_show_all (window);

	return 0;
}

