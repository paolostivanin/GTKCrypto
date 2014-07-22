#include <gtk/gtk.h>
#include <glib.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "polcrypt.h"

#define NUM_OF_BUTTONS 6
#define NUM_OF_FRAMES 2
#define NUM_OF_BOXES 2

GCRY_THREAD_OPTION_PTHREAD_IMPL;

GtkWidget *do_mainwin (GtkApplication *app, struct widget_t *);
static void choose_file (GtkWidget *button, struct widget_t *);


static void
quit (GSimpleAction *action,
	  GVariant *parameter,
	  gpointer app)
{
	g_application_quit (G_APPLICATION(app));
}

static void
about (GSimpleAction *action, 
	   GVariant *parameter,
	   gpointer data)
{
        const gchar *authors[] =
        {
                "Paolo Stivanin <info@paolostivanin.com>",
                NULL,
        };
		
		const gchar *my_icon = "/usr/share/icons/hicolor/128x128/apps/polcrypt.png";
        GError *error = NULL;
        GdkPixbuf *logo_about = gdk_pixbuf_new_from_file_at_size(my_icon, 64, 64, &error);

        GtkWidget *a_dialog = gtk_about_dialog_new ();
        gtk_about_dialog_set_program_name (GTK_ABOUT_DIALOG (a_dialog), "PolCrypt");
        gtk_about_dialog_set_logo (GTK_ABOUT_DIALOG (a_dialog), logo_about);
        gtk_about_dialog_set_version (GTK_ABOUT_DIALOG (a_dialog), VERSION);
        gtk_about_dialog_set_copyright (GTK_ABOUT_DIALOG (a_dialog), "Copyright (C) 2014");
        gtk_about_dialog_set_comments (GTK_ABOUT_DIALOG (a_dialog),
									  _("Encrypt and decrypt a file using different cipher algo and different ciper mode or"
									  " compute its hash using different hash algo"));
        gtk_about_dialog_set_license(GTK_ABOUT_DIALOG(a_dialog),
									"This program is free software: you can redistribute it and/or modify it under the terms"
									" of the GNU General Public License as published by the Free Software Foundation, either version 3 of"
									" the License, or (at your option) any later version.\n"
									"This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even"
									" the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. "
									"See the GNU General Public License for more details.\n"
									"You should have received a copy of the GNU General Public License along with this program."
									"\nIf not, see http://www.gnu.org/licenses\n\nPolCrypt is Copyright (C) 2014 by Paolo Stivanin.\n");
        gtk_about_dialog_set_wrap_license (GTK_ABOUT_DIALOG (a_dialog), TRUE);
        gtk_about_dialog_set_website (GTK_ABOUT_DIALOG (a_dialog), "https://www.paolostivanin.com");
        gtk_about_dialog_set_authors (GTK_ABOUT_DIALOG (a_dialog), authors);

        gtk_dialog_run(GTK_DIALOG (a_dialog));
        gtk_widget_destroy (a_dialog);
}


static void
startup (GtkApplication *application,
		 gpointer data)
{
	static const GActionEntry actions[] = {
		{ "about", about },
		{ "quit", quit }
	};
	
	const gchar *quit_accels[2] = { "<Ctrl>Q", NULL };
	
	GMenu *menu, *section;

	g_action_map_add_action_entries (G_ACTION_MAP (application),
									 actions, G_N_ELEMENTS (actions),
									 application);
	
	gtk_application_set_accels_for_action (GTK_APPLICATION (application),
									 "app.quit",
									 quit_accels);
							
	menu = g_menu_new ();
	
	section = g_menu_new ();
	g_menu_append (section, _("About"), "app.about");
	g_menu_append_section (G_MENU (menu), NULL, G_MENU_MODEL (section));
	g_object_unref (section);
	
	section = g_menu_new ();
	g_menu_append (section, _("Quit"),  "app.quit");
	g_menu_append_section (G_MENU (menu), NULL, G_MENU_MODEL (section));
	g_object_unref (section);

	gtk_application_set_app_menu (application, G_MENU_MODEL (menu));
	g_object_unref (menu);
}


static void
activate (GtkApplication *app,
		  struct widget_t *Widget)
{
	if (glib_check_version (2, 36, 0) != NULL){
		fprintf(stderr, "The required version of GLib is 2.36.0 or greater.");
		return;
	}
	if (gtk_check_version (3, 12, 0) != NULL){
		fprintf(stderr, "The required version of GTK+ is 3.12.0 or greater.");
		return;
	}
	
	
	GtkWidget *button[NUM_OF_BUTTONS];
	GtkWidget *frame[2];
	GtkWidget *box[2];
	GtkWidget *grid;
	
	gint i, j=0;
	const gchar *buttonLabel[] = {"File", "Text", "Compute Hash", "Quit"};
	const gchar *frameLabel[] = {"Encrypt", "Decrypt"};
	const gchar *buttonName[] = {"butEn", "butDe", "butEnTxt", "butDeTxt", "butHa", "butQ"}; //button 0,1,2,3,4,5

	Widget->mainwin = do_mainwin(app, Widget);
	
	for (i=0; i<NUM_OF_BUTTONS; i++){
		if(i == 5) j++;
		button[i] = gtk_button_new_with_label (buttonLabel[j]);
		gtk_widget_set_name (GTK_WIDGET (button[i]), buttonName[i]);
		if(i%2 != 0) j++;
	}
	
	for (i=0; i<NUM_OF_FRAMES; i++){
		frame[i] = gtk_frame_new (frameLabel[i]);
	}
	
	for (i=0; i<NUM_OF_BOXES; i++){
		box[i] = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
	}
	
	gtk_box_pack_start (GTK_BOX (box[0]), button[0], TRUE, TRUE, 2);
	gtk_box_pack_start (GTK_BOX (box[0]), button[2], TRUE, TRUE, 2);
	gtk_container_add (GTK_CONTAINER (frame[0]), box[0]);
	
	gtk_box_pack_start (GTK_BOX (box[1]), button[1], TRUE, TRUE, 2);
	gtk_box_pack_start (GTK_BOX (box[1]), button[3], TRUE, TRUE, 2);
	gtk_container_add (GTK_CONTAINER (frame[1]), box[1]);
	
	g_signal_connect (button[0], "clicked", G_CALLBACK (choose_file), Widget);
	g_signal_connect (button[1], "clicked", G_CALLBACK (choose_file), Widget);
	g_signal_connect (button[2], "clicked", G_CALLBACK (quit), app);
	g_signal_connect (button[3], "clicked", G_CALLBACK (quit), app);
	g_signal_connect (button[4], "clicked", G_CALLBACK (quit), app);
	g_signal_connect (button[5], "clicked", G_CALLBACK (quit), app);
	
	grid = gtk_grid_new();
	gtk_container_add (GTK_CONTAINER (Widget->mainwin), grid);
	gtk_grid_set_row_homogeneous (GTK_GRID (grid), TRUE);
	gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 5);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 5);

	gtk_grid_attach (GTK_GRID (grid), frame[0], 0, 0, 3, 2);
	gtk_grid_attach (GTK_GRID (grid), frame[1], 0, 2, 3, 2);
	gtk_grid_attach (GTK_GRID (grid), button[4], 0, 5, 3, 1);
	gtk_grid_attach (GTK_GRID  (grid), button[5], 0, 6, 3, 1);
	
	gtk_widget_show_all (Widget->mainwin);
}


gint
main(int argc,
	char *argv[])
{
	gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	if (!gcry_check_version (GCRYPT_MIN_VER)){
		fprintf(stderr, "libgcrypt min version required: %s\n", GCRYPT_MIN_VER);
		return -1;
	}
	gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	
	struct widget_t Widget;
	
	const gchar *my_icon = "/usr/share/icons/hicolor/128x128/apps/polcrypt.png";

	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, LOCALE_DIR);
	textdomain (PACKAGE);

	GtkApplication *app;
	gint status;
	GError *err = NULL;
	GdkPixbuf *logo = gdk_pixbuf_new_from_file (my_icon, &err);
	gtk_window_set_default_icon (logo);
	
	app = gtk_application_new ("org.gtk.polcrypt", G_APPLICATION_FLAGS_NONE);
	g_signal_connect (app, "startup", G_CALLBACK (startup), NULL);
	g_signal_connect (app, "activate", G_CALLBACK (activate), &Widget);
	status = g_application_run (G_APPLICATION (app), argc, argv);
	g_object_unref (app);
	return status;
}

GtkWidget
*do_mainwin(GtkApplication *app,
			struct widget_t *Widget)
{
	static GtkWidget *window = NULL;
	const gchar *my_icon = "/usr/share/icons/hicolor/128x128/apps/polcrypt.png";
	GtkWidget *headerBar;
	GtkWidget *box;
	GError *err = NULL;

	window = gtk_application_window_new(app);
	gtk_window_set_application (GTK_WINDOW (window), GTK_APPLICATION (app));
	gtk_window_set_position (GTK_WINDOW (window), GTK_WIN_POS_CENTER);
	gtk_window_set_resizable (GTK_WINDOW (window), FALSE);
	gtk_window_set_icon_from_file (GTK_WINDOW (window), my_icon, &err);
	gtk_container_set_border_width (GTK_CONTAINER (window), 10);
	
	gtk_widget_set_size_request (GTK_WIDGET (window), 350, 400);

	gchar headertext[HEADERBAR_BUF];
	g_snprintf (headertext, HEADERBAR_BUF-1, _("PolCrypt %s"), VERSION);
	headertext[HEADERBAR_BUF-1] = '\0';

	headerBar = gtk_header_bar_new ();
	gtk_header_bar_set_show_close_button (GTK_HEADER_BAR (headerBar), TRUE);
	gtk_header_bar_set_title (GTK_HEADER_BAR (headerBar), headertext);
	gtk_header_bar_set_has_subtitle (GTK_HEADER_BAR (headerBar), FALSE);

	box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_style_context_add_class (gtk_widget_get_style_context (box), "linked");
		
	gtk_window_set_titlebar (GTK_WINDOW (window), headerBar);
	
	return window;
}

static void
choose_file(GtkWidget *button, struct widget_t *Widget)
{
	GtkWidget *fileDialog;
	GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
	fileDialog = gtk_file_chooser_dialog_new (_("Choose File"),
											  GTK_WINDOW (Widget->mainwin),
											  action,
											  _("OK"), GTK_RESPONSE_ACCEPT,
											  _("Cancel"), GTK_RESPONSE_REJECT,
											  NULL);
	gint result = gtk_dialog_run (GTK_DIALOG (fileDialog));
	switch (result)
	{
		case GTK_RESPONSE_ACCEPT:
			g_print ("%s\n", gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (fileDialog)));
			break;
		default:
			break;
	}
	
	gtk_widget_destroy (fileDialog);
}
