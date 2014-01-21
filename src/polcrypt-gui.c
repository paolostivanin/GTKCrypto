#include <gtk/gtk.h>
#include <glib.h>
//#include <stdio.h>
#include <string.h>
//#include <stdlib.h>
//#include <unistd.h>
//#include <ctype.h>

struct widget{
	GtkWidget *mainwin;
};

int main(int argc, char **argv){
	struct widget s_Widget;
	GtkWidget *but, *grid;
	
	gtk_init(&argc, &argv);
	
	s_Widget.mainwin = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_position(GTK_WINDOW(s_Widget.mainwin), GTK_WIN_POS_CENTER);
	gtk_window_set_title(GTK_WINDOW(s_Widget.mainwin), "PolCrypt");
	gtk_window_set_resizable(GTK_WINDOW(s_Widget.mainwin), FALSE);
	g_signal_connect(s_Widget.mainwin, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	gtk_container_set_border_width(GTK_CONTAINER(s_Widget.mainwin), 10);
	
	but = gtk_button_new_with_label("OK");
	g_signal_connect(but, "clicked", G_CALLBACK (gtk_main_quit), NULL);
	
	grid = gtk_grid_new();
	gtk_container_add(GTK_CONTAINER(s_Widget.mainwin), grid);
	gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);
	gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
	gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
	gtk_grid_set_column_spacing(GTK_GRID(grid), 5);
	
	//numero colonna, numero riga, colonne da occupare, righe da occupare. Colonne e righe sono aggiunte automaticamente
	gtk_grid_attach(GTK_GRID(grid), but, 0, 0, 1, 1);

	gtk_widget_show_all(s_Widget.mainwin);
	
	gtk_main();
	
	return 0;
}
