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

/* ToDo:
 * - hash;
 * - thread;
 * - when an error occurs show up a dialog instead of a notification
 */

GtkWidget *do_mainwin (GtkApplication *, struct widget_t *);
static void choose_file (GtkWidget *, struct widget_t *);
static void pwd_dialog (GtkWidget *, struct widget_t *, gint);
gint crypt_file (struct widget_t *, gint);
static GtkWidget *create_popover (GtkWidget *, GtkPositionType, struct widget_t *);
static void hide_menu (struct widget_t *);
static gint check_pwd (GtkWidget *, GtkWidget *);
static void toggle_changed_cb (GtkToggleButton *, GtkWidget *);
static void compute_sha2 (struct hashWidget_t *, gint);
static void compute_sha3 (struct hashWidget_t *, gint);


static void
quit (	GSimpleAction *action,
	GVariant *parameter,
	gpointer app)
{
	g_application_quit (G_APPLICATION(app));
}

static void
about (	GSimpleAction *action, 
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
startup (	GtkApplication *application,
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
activate (	GtkApplication *app,
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
main (	int argc,
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
*do_mainwin (	GtkApplication *app,
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
choose_file (	GtkWidget *button,
		struct widget_t *Widget)
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
			Widget->filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (fileDialog));
			const gchar *name = gtk_widget_get_name (GTK_WIDGET (button));
			if (g_strcmp0 (name, "butEn") == 0)
				pwd_dialog (fileDialog, Widget, ENCRYPT);
			else if (g_strcmp0 (name, "butDe") == 0)
				pwd_dialog (fileDialog, Widget, DECRYPT);
				
			g_free (Widget->filename);
			break;
		
		default:
			break;
	}
	
	gtk_widget_destroy (fileDialog);
}


static void
pwd_dialog (	GtkWidget *fileDialog,
		struct widget_t *Widget,
		gint cryptMode)
{
	gtk_widget_hide (fileDialog);
	
	GtkWidget *dialog, *contentArea, *grid, *infoArea, *label[2];
	GtkWidget *headerBar, *box, *image, *popover;
	GtkWidget *infoBar, *infoLabel;
	GIcon *icon;
	GValue leftMargin = G_VALUE_INIT;
	GValue topMargin = G_VALUE_INIT;
	gint result;
	
	restart:
	if (cryptMode == ENCRYPT)
	{
		headerBar = gtk_header_bar_new ();
		gtk_header_bar_set_show_close_button (GTK_HEADER_BAR (headerBar), FALSE);
		gtk_header_bar_set_title (GTK_HEADER_BAR (headerBar), _("Encryption Password"));
		gtk_header_bar_set_has_subtitle (GTK_HEADER_BAR (headerBar), FALSE);
		
		box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
		gtk_style_context_add_class (gtk_widget_get_style_context (box), "linked");
		icon = g_themed_icon_new ("emblem-system-symbolic");
		image = gtk_image_new_from_gicon (icon, GTK_ICON_SIZE_BUTTON);
		g_object_unref (icon);
	
		Widget->menu = gtk_toggle_button_new ();
		gtk_container_add (GTK_CONTAINER (Widget->menu), image);
		gtk_widget_set_tooltip_text (GTK_WIDGET (Widget->menu), _("Settings"));
	
		popover = create_popover (Widget->menu, GTK_POS_TOP, Widget);
		gtk_popover_set_modal (GTK_POPOVER (popover), TRUE);
		g_signal_connect (Widget->menu, "toggled", G_CALLBACK (toggle_changed_cb), popover);
	
		gtk_header_bar_pack_start(GTK_HEADER_BAR (headerBar), GTK_WIDGET(Widget->menu));
	}
	
	GtkDialogFlags flags = GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT;
	dialog = gtk_dialog_new_with_buttons ("Password",
				     GTK_WINDOW (Widget->mainwin),
				     flags,
				     _("OK"), GTK_RESPONSE_ACCEPT,
				     _("Cancel"), GTK_RESPONSE_REJECT,
				     NULL);
	
	contentArea = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
	if (cryptMode == ENCRYPT)
	{
		gtk_window_set_titlebar (GTK_WINDOW (dialog), headerBar);
		gtk_widget_add_events (GTK_WIDGET (dialog), GDK_BUTTON_PRESS_MASK);
		g_signal_connect_swapped (dialog, "button-press-event", G_CALLBACK(hide_menu), Widget);
	}
	
	label[0] = gtk_label_new ( _("Type password"));
	if (cryptMode == ENCRYPT)
	{
		label[1] = gtk_label_new ( _("Retype password"));
		Widget->pwdEntry[1] = gtk_entry_new ();
		gtk_entry_set_visibility (GTK_ENTRY (Widget->pwdEntry[1]), FALSE);
	}
	
	Widget->pwdEntry[0] = gtk_entry_new ();
	gtk_entry_set_visibility (GTK_ENTRY (Widget->pwdEntry[0]), FALSE);
	
	gtk_widget_set_size_request (dialog, 150, 100);
	
	infoBar = gtk_info_bar_new ();
	
	if(cryptMode == ENCRYPT)
		infoLabel = gtk_label_new ( _("Encrypting and deleting the file can take some minutes depending on the file size..."));
	else
		infoLabel = gtk_label_new ( _("Decrypting the file can take some minutes depending on the file size..."));
	
	gtk_label_set_justify (GTK_LABEL (infoLabel), GTK_JUSTIFY_CENTER);
	gtk_info_bar_set_message_type (GTK_INFO_BAR (infoBar), GTK_MESSAGE_INFO);
	infoArea = gtk_info_bar_get_content_area (GTK_INFO_BAR (infoBar));
	gtk_container_add (GTK_CONTAINER (infoArea), infoLabel);
	
	if (!G_IS_VALUE (&leftMargin)) g_value_init (&leftMargin, G_TYPE_UINT);
	g_value_set_uint (&leftMargin, 2);
	g_object_set_property (G_OBJECT (Widget->pwdEntry[0]), "margin-left", &leftMargin);
	if (cryptMode == ENCRYPT)
		g_object_set_property (G_OBJECT (Widget->pwdEntry[1]), "margin-left", &leftMargin);
	
	if (cryptMode == DECRYPT)
	{
		if (!G_IS_VALUE (&topMargin)) g_value_init (&topMargin, G_TYPE_UINT);
		g_value_set_uint (&topMargin, 10);
		g_object_set_property (G_OBJECT (label[0]), "margin-top", &topMargin);
		g_object_set_property (G_OBJECT (Widget->pwdEntry[0]), "margin-top", &topMargin);
	}
	
	grid = gtk_grid_new ();
	gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 5);
	
	gtk_grid_attach (GTK_GRID (grid), label[0], 0, 0, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), Widget->pwdEntry[0], 1, 0, 2, 1);
	if(cryptMode == ENCRYPT)
	{
		gtk_grid_attach (GTK_GRID (grid), label[1], 0, 1, 1, 1);
		gtk_grid_attach (GTK_GRID (grid), Widget->pwdEntry[1], 1, 1, 2, 1);
		gtk_grid_attach (GTK_GRID (grid), infoBar, 0, 2, 3, 1);
	}
	else
	{
		gtk_grid_attach (GTK_GRID (grid), infoBar, 0, 1, 3, 1);
	}

	gtk_container_add (GTK_CONTAINER (contentArea), grid);
	gtk_widget_show_all (dialog);
	
	result = gtk_dialog_run (GTK_DIALOG(dialog));
	switch (result)
	{
		case GTK_RESPONSE_ACCEPT:
			if (cryptMode == ENCRYPT)
			{
				if (check_pwd (Widget->pwdEntry[0], Widget->pwdEntry[1]) == -1)
				{
					g_printerr ("Passwords are different or password is < 8 chars. Try again\n");
					gtk_widget_destroy (dialog);
					goto restart;
				}
				else
				{
					crypt_file (Widget, ENCRYPT);
					gtk_widget_destroy (dialog);					
				}

			}
			else
			{
				result = crypt_file (Widget, DECRYPT);
				gtk_widget_destroy (dialog);
				if (result == -5) goto restart;
			}
			break;
			
		case GTK_RESPONSE_REJECT:
			gtk_widget_destroy (dialog);
			break;
			
		default:
			g_printerr ("Exiting...\n");
			gtk_widget_destroy (dialog);
	}
}


static gint
check_pwd (	GtkWidget *passEntry1,
		GtkWidget *passEntry2)
{
	const gchar *pw1 = gtk_entry_get_text (GTK_ENTRY (passEntry1));
	const gchar *pw2 = gtk_entry_get_text (GTK_ENTRY (passEntry2));
	
	if (g_strcmp0 (pw1, pw2) != 0)
		return -1;
		
	else if (g_utf8_strlen (pw1, -1) < 8)
		return -1;

	else
		return 0;
}    


static GtkWidget
*create_popover (	GtkWidget *parent,
			GtkPositionType pos,
			struct widget_t *Widget)
{

	GtkWidget *popover, *box[3], *label[2], *hline[2], *vline;
	const gchar *algo[] = {"Serpent", "Twofish", "Camellia-256"};
	gint i, j;

	label[0] = gtk_label_new(_("Cipher Algo"));
	label[1] = gtk_label_new(_("Cipher Mode"));
	
	hline[0] = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
	hline[1] = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);

	box[0] = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	box[1] = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
	box[2] = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	
	gtk_box_set_homogeneous (GTK_BOX (box[1]), FALSE);

	popover = gtk_popover_new (parent);
	gtk_popover_set_position (GTK_POPOVER (popover), pos);

	Widget->radioButton[0] = gtk_radio_button_new_with_label_from_widget (NULL, "AES-256");
	for(i=1, j=0; i<4; i++, j++)
		Widget->radioButton[i] = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON (Widget->radioButton[0]), algo[j]);
	
	Widget->radioButton[4] = gtk_radio_button_new_with_label_from_widget(NULL, "CBC");
	Widget->radioButton[5] = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(Widget->radioButton[4]), "CTR");

	gtk_box_pack_start (GTK_BOX (box[0]), label[0], TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box[0]), hline[0], TRUE, TRUE, 0);
	for(i=0; i<4; i++)
		gtk_box_pack_start (GTK_BOX (box[0]), Widget->radioButton[i], TRUE, TRUE, 0);
	
	gtk_box_pack_start (GTK_BOX (box[2]), label[1], FALSE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box[2]), hline[1], FALSE, TRUE, 0); //problema
	for(i=4; i<6; i++)
		gtk_box_pack_start (GTK_BOX (box[2]), Widget->radioButton[i], FALSE, TRUE, 0);
	
	vline = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
	gtk_box_pack_start( GTK_BOX(box[1]), box[0], TRUE, TRUE, 0); //problema
	gtk_box_pack_start (GTK_BOX (box[1]), vline, TRUE, TRUE, 0);
	gtk_box_pack_start( GTK_BOX(box[1]), box[2], FALSE, TRUE, 0); //problema

	g_object_set(Widget->radioButton[0], "active", TRUE, NULL);
	g_object_set(Widget->radioButton[4], "active", TRUE, NULL);
	
	gtk_container_add (GTK_CONTAINER (popover), box[1]);
	gtk_container_set_border_width (GTK_CONTAINER (popover), 4);
	gtk_widget_show_all (box[1]);
	
	return popover; 
}

static void
hide_menu (struct widget_t *Widget)
{
	if(gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (Widget->menu)))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (Widget->menu), FALSE);
}

static void
toggle_changed_cb (	GtkToggleButton *button,
			GtkWidget *popover)
{
	gtk_widget_set_visible (popover, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button)));
}
