#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "gtkcrypto.h"
#include "main.h"


static void choose_file_dialog (GtkWidget *, struct main_vars *);
static void pwd_dialog (GtkWidget *, struct main_vars *);
static void hide_menu (struct main_vars *);
static void toggle_changed_cb (GtkToggleButton *, GtkWidget *);
static void compute_hash_dialog (GtkWidget *, GtkWidget *, const gchar *);

const gchar *bt_names[] = {"BtMd5", "BtGost", "BtSha1", "BtSha256", "BtSha3_256", "BtSha384", "BtSha3_384", "BtSha512", "BtSha3_512", "BtWhirl" };
gpointer (*hash_func[NUM_OF_HASH])(gpointer) = {compute_md5, compute_gost94, compute_sha1, compute_sha2, compute_sha3, compute_sha2, compute_sha3, compute_sha2, compute_sha3, compute_whirlpool};

static void
quit (	GSimpleAction __attribute__((__unused__)) *action,
		GVariant __attribute__((__unused__)) *parameter,
		gpointer app)
{
	g_application_quit (G_APPLICATION(app));
}


static void
about (	GSimpleAction __attribute__((__unused__)) *action, 
		GVariant __attribute__((__unused__)) *parameter,
		gpointer __attribute__((__unused__)) data)
{

	const gchar *authors[] =
	{
			"Paolo Stivanin <info@paolostivanin.com>",
			NULL,
	};

	GdkPixbuf *logo = create_logo (TRUE);

	GtkWidget *a_dialog = gtk_about_dialog_new ();
	gtk_about_dialog_set_program_name (GTK_ABOUT_DIALOG (a_dialog), "GTKCrypto");
	if (logo != NULL)
		gtk_about_dialog_set_logo (GTK_ABOUT_DIALOG (a_dialog), logo);
   
	gtk_about_dialog_set_version (GTK_ABOUT_DIALOG (a_dialog), VERSION);
	gtk_about_dialog_set_copyright (GTK_ABOUT_DIALOG (a_dialog), "Copyright (C) 2015");
	gtk_about_dialog_set_comments (GTK_ABOUT_DIALOG (a_dialog),
				_("Encrypt and decrypt files using different cipher algo and different cipher mode or"
				" compute their hash using different algo"));
	gtk_about_dialog_set_license(GTK_ABOUT_DIALOG(a_dialog),
				"This program is free software: you can redistribute it and/or modify it under the terms"
				" of the GNU General Public License as published by the Free Software Foundation, either version 3 of"
				" the License, or (at your option) any later version.\n"
				"This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even"
				" the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. "
				"See the GNU General Public License for more details.\n"
				"You should have received a copy of the GNU General Public License along with this program."
				"\nIf not, see http://www.gnu.org/licenses\n\nGTKCrypto is Copyright (C) 2015 by Paolo Stivanin.\n");
	gtk_about_dialog_set_wrap_license (GTK_ABOUT_DIALOG (a_dialog), TRUE);
	gtk_about_dialog_set_website (GTK_ABOUT_DIALOG (a_dialog), "http://www.paolostivanin.com");
	gtk_about_dialog_set_authors (GTK_ABOUT_DIALOG (a_dialog), authors);

	gtk_dialog_run(GTK_DIALOG (a_dialog));
	gtk_widget_destroy (a_dialog);
}


static void
startup (	GtkApplication *application,
			gpointer __attribute__((__unused__)) data)
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
			struct main_vars *main_var)
{
	GtkWidget *button[NUM_OF_BUTTONS];
	GtkWidget *frame[2];
	GtkWidget *box[2];
	GtkWidget *grid;
	
	gint i, j=0;
	const gchar *button_label[] = {"File", "Text", "Compute Hash", "Quit"};
	const gchar *frame_label[] = {"Encrypt", "Decrypt"};
	const gchar *button_name[] = {"butEn", "butDe", "butEnTxt", "butDeTxt", "butHa", "butQ"}; //button 0,1,2,3,4,5

	main_var->main_window = do_mainwin (app);
	
	if (!gcry_check_version ("1.5.0"))
	{
		error_dialog ( _("The required version of Gcrypt is 1.5.0 or greater."), main_var->main_window);
		return;
	}
		
	for (i=0; i<NUM_OF_BUTTONS; i++)
	{
		if(i == 5) j++;
		button[i] = gtk_button_new_with_label (button_label[j]);
		gtk_widget_set_name (GTK_WIDGET (button[i]), button_name[i]);
		if(i%2 != 0) j++;
	}
	
	for (i=0; i<NUM_OF_FRAMES; i++)
		frame[i] = gtk_frame_new (frame_label[i]);
	
	for (i=0; i<NUM_OF_BOXES; i++)
		box[i] = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
	
	gtk_box_pack_start (GTK_BOX (box[0]), button[0], TRUE, TRUE, 2);
	gtk_box_pack_start (GTK_BOX (box[0]), button[2], TRUE, TRUE, 2);
	gtk_container_add (GTK_CONTAINER (frame[0]), box[0]);
	
	gtk_box_pack_start (GTK_BOX (box[1]), button[1], TRUE, TRUE, 2);
	gtk_box_pack_start (GTK_BOX (box[1]), button[3], TRUE, TRUE, 2);
	gtk_container_add (GTK_CONTAINER (frame[1]), box[1]);
	
	g_signal_connect (button[0], "clicked", G_CALLBACK (choose_file_dialog), main_var);
	g_signal_connect (button[1], "clicked", G_CALLBACK (choose_file_dialog), main_var);
	g_signal_connect (button[2], "clicked", G_CALLBACK (text_dialog), main_var->main_window);
	g_signal_connect (button[3], "clicked", G_CALLBACK (text_dialog), main_var->main_window);
	g_signal_connect (button[4], "clicked", G_CALLBACK (choose_file_dialog), main_var);
	g_signal_connect (button[5], "clicked", G_CALLBACK (quit), app);
	
	grid = gtk_grid_new ();
	gtk_container_add (GTK_CONTAINER (main_var->main_window), grid);
	gtk_grid_set_row_homogeneous (GTK_GRID (grid), TRUE);
	gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 5);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 5);

	gtk_grid_attach (GTK_GRID (grid), frame[0], 0, 0, 3, 2);
	gtk_grid_attach (GTK_GRID (grid), frame[1], 0, 2, 3, 2);
	gtk_grid_attach (GTK_GRID (grid), button[4], 0, 5, 3, 1);
	gtk_grid_attach (GTK_GRID  (grid), button[5], 0, 6, 3, 1);
	
	gtk_widget_show_all (main_var->main_window);
}


gint
main (	int argc,
		char *argv[])
{
	gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	
	struct main_vars main_var;
	
	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, LOCALE_DIR);
	textdomain (PACKAGE);

	GtkApplication *app;
	gint status;
	
	GdkPixbuf *logo = create_logo (FALSE);
		
	if (logo != NULL)
		gtk_window_set_default_icon (logo);
	
	app = gtk_application_new ("org.gtk.gtkcrypto", G_APPLICATION_FLAGS_NONE);
	g_signal_connect (app, "startup", G_CALLBACK (startup), NULL);
	g_signal_connect (app, "activate", G_CALLBACK (activate), &main_var);
	status = g_application_run (G_APPLICATION (app), argc, argv);
	g_object_unref (app);
	return status;
}


GtkWidget
*do_mainwin (GtkApplication *app)
{
	static GtkWidget *window = NULL;
	GtkWidget *header_bar;
	GtkWidget *box;
	
	GdkPixbuf *logo = create_logo (0);

	window = gtk_application_window_new (app);
	gtk_window_set_application (GTK_WINDOW (window), GTK_APPLICATION (app));
	gtk_window_set_position (GTK_WINDOW (window), GTK_WIN_POS_CENTER);
	gtk_window_set_resizable (GTK_WINDOW (window), FALSE);
	
	if (logo != NULL)
		gtk_window_set_icon (GTK_WINDOW (window), logo);
		
	gtk_container_set_border_width (GTK_CONTAINER (window), 10);
	
	gtk_widget_set_size_request (GTK_WIDGET (window), 350, 400);

	gchar headertext[HEADERBAR_BUF];
	g_snprintf (headertext, HEADERBAR_BUF-1, _("GTKCrypto %s"), VERSION);
	headertext[HEADERBAR_BUF-1] = '\0';

	header_bar = gtk_header_bar_new ();
	gtk_header_bar_set_show_close_button (GTK_HEADER_BAR (header_bar), TRUE);
	gtk_header_bar_set_title (GTK_HEADER_BAR (header_bar), headertext);
	gtk_header_bar_set_has_subtitle (GTK_HEADER_BAR (header_bar), FALSE);

	box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_style_context_add_class (gtk_widget_get_style_context (box), "linked");
		
	gtk_window_set_titlebar (GTK_WINDOW (window), header_bar);
	
	return window;
}


static void
choose_file_dialog (GtkWidget *button,
					struct main_vars *main_var)
{
	GtkWidget *file_dialog;
	GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
	
	file_dialog = gtk_file_chooser_dialog_new ( _("Choose File"),
						  GTK_WINDOW (main_var->main_window),
						  action,
						  _("OK"), GTK_RESPONSE_ACCEPT,
						  _("Cancel"), GTK_RESPONSE_REJECT,
						  NULL);
	gint result = gtk_dialog_run (GTK_DIALOG (file_dialog));
	switch (result)
	{
		case GTK_RESPONSE_ACCEPT:
			main_var->filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (file_dialog));
			if (!g_utf8_validate (main_var->filename, -1, NULL))
			{
				error_dialog ( _("The name of the file you chose isn't a valid UTF-8 string."), main_var->main_window);
				g_free (main_var->filename);
				break;
			}
			
			const gchar *name = gtk_widget_get_name (GTK_WIDGET (button));
			if (g_strcmp0 (name, "butEn") == 0)
			{
				main_var->encrypt = TRUE;
				pwd_dialog (file_dialog, main_var);
			}
			else if (g_strcmp0 (name, "butDe") == 0)
			{
				main_var->encrypt = FALSE;
				pwd_dialog (file_dialog, main_var);
			}
			else if (g_strcmp0 (name, "butHa") == 0)
				compute_hash_dialog (file_dialog, main_var->main_window, main_var->filename);
				
			g_free (main_var->filename);
			break;
		
		default:
			break;
	}
	
	gtk_widget_destroy (file_dialog);
}


static void
create_dialog (struct main_vars *main_var)
{
	GtkWidget *content_area;
	gint result;
	
	main_var->bar_dialog = gtk_dialog_new_with_buttons ("Progress Bar",
				     GTK_WINDOW (main_var->main_window),
				     GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
				     _("Close"), GTK_RESPONSE_REJECT,
				     NULL);
				     
	gtk_widget_set_size_request (main_var->bar_dialog, 250, 80);
	gtk_dialog_set_response_sensitive (GTK_DIALOG (main_var->bar_dialog), GTK_RESPONSE_REJECT, FALSE);	   
				     
	content_area = gtk_dialog_get_content_area (GTK_DIALOG (main_var->bar_dialog));
	main_var->pBar = gtk_progress_bar_new ();
	
	gtk_container_add (GTK_CONTAINER (content_area), main_var->pBar);
	gtk_widget_show_all (main_var->bar_dialog);
	
	GThread *n = g_thread_new (NULL, crypt_file, main_var);

	result = gtk_dialog_run (GTK_DIALOG (main_var->bar_dialog));
	switch (result)
	{
		case GTK_RESPONSE_REJECT:
			g_thread_join (n);
			break;
		default:
			break;
	}

	gtk_widget_destroy (main_var->bar_dialog);
}


static void
pwd_dialog (GtkWidget *file_dialog,
			struct main_vars *main_var)
{
	gtk_widget_hide (file_dialog);
	
	GtkWidget *dialog, *content_area, *grid, *info_area, *label[2];
	GtkWidget *header_bar = NULL, *box, *image, *popover;
	GtkWidget *info_bar, *info_label;
	GIcon *icon;
	GValue left_margin = G_VALUE_INIT;
	GValue top_margin = G_VALUE_INIT;
	gint result, ret_val;
			
	restart:
	if (main_var->encrypt)
	{
		header_bar = gtk_header_bar_new ();
		gtk_header_bar_set_show_close_button (GTK_HEADER_BAR (header_bar), FALSE);
		gtk_header_bar_set_title (GTK_HEADER_BAR (header_bar), _("Encryption Password"));
		gtk_header_bar_set_has_subtitle (GTK_HEADER_BAR (header_bar), FALSE);
		
		box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
		gtk_style_context_add_class (gtk_widget_get_style_context (box), "linked");
		icon = g_themed_icon_new ("emblem-system-symbolic");
		image = gtk_image_new_from_gicon (icon, GTK_ICON_SIZE_BUTTON);
		g_object_unref (icon);
	
		main_var->menu = gtk_toggle_button_new ();
		gtk_container_add (GTK_CONTAINER (main_var->menu), image);
		gtk_widget_set_tooltip_text (GTK_WIDGET (main_var->menu), _("Settings"));
	
		popover = create_popover (main_var->menu, GTK_POS_TOP, main_var);
		gtk_popover_set_modal (GTK_POPOVER (popover), TRUE);
		g_signal_connect (main_var->menu, "toggled", G_CALLBACK (toggle_changed_cb), popover);
	
		gtk_header_bar_pack_start (GTK_HEADER_BAR (header_bar), GTK_WIDGET(main_var->menu));
	}
	
	GtkDialogFlags flags = GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT;
	dialog = gtk_dialog_new_with_buttons ("Password",
				     GTK_WINDOW (main_var->main_window),
				     flags,
				     _("OK"), GTK_RESPONSE_ACCEPT,
				     _("Cancel"), GTK_RESPONSE_REJECT,
				     NULL);
	
	content_area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
	if (main_var->encrypt)
	{
		gtk_window_set_titlebar (GTK_WINDOW (dialog), header_bar);
		gtk_widget_add_events (GTK_WIDGET (dialog), GDK_BUTTON_PRESS_MASK);
		g_signal_connect_swapped (dialog, "button-press-event", G_CALLBACK(hide_menu), main_var);
	}
	
	label[0] = gtk_label_new ( _("Type password"));
	if (main_var->encrypt)
	{
		label[1] = gtk_label_new ( _("Retype password"));
		main_var->pwd_entry[1] = gtk_entry_new ();
		gtk_entry_set_visibility (GTK_ENTRY (main_var->pwd_entry[1]), FALSE);
	}
	
	main_var->pwd_entry[0] = gtk_entry_new ();
	gtk_entry_set_visibility (GTK_ENTRY (main_var->pwd_entry[0]), FALSE);
	
	gtk_widget_set_size_request (dialog, 150, 100);
	
	info_bar = gtk_info_bar_new ();
	
	if (main_var->encrypt)
		info_label = gtk_label_new ( _("Encrypting and deleting the file can take some minutes depending on the file size..."));
	else
		info_label = gtk_label_new ( _("Decrypting the file can take some minutes depending on the file size..."));
	
	gtk_label_set_justify (GTK_LABEL (info_label), GTK_JUSTIFY_CENTER);
	gtk_info_bar_set_message_type (GTK_INFO_BAR (info_bar), GTK_MESSAGE_INFO);
	info_area = gtk_info_bar_get_content_area (GTK_INFO_BAR (info_bar));
	gtk_container_add (GTK_CONTAINER (info_area), info_label);
	
	if (!G_IS_VALUE (&left_margin))
		g_value_init (&left_margin, G_TYPE_UINT);
		
	g_value_set_uint (&left_margin, 2);
	g_object_set_property (G_OBJECT (main_var->pwd_entry[0]), "margin-start", &left_margin);
	
	if (main_var->encrypt)
		g_object_set_property (G_OBJECT (main_var->pwd_entry[1]), "margin-start", &left_margin);
	
	if (!main_var->encrypt)
	{
		if (!G_IS_VALUE (&top_margin))
			g_value_init (&top_margin, G_TYPE_UINT);
			
		g_value_set_uint (&top_margin, 10);
		g_object_set_property (G_OBJECT (label[0]), "margin-top", &top_margin);
		g_object_set_property (G_OBJECT (main_var->pwd_entry[0]), "margin-top", &top_margin);
	}
	
	grid = gtk_grid_new ();
	gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 5);
	
	gtk_grid_attach (GTK_GRID (grid), label[0], 0, 0, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), main_var->pwd_entry[0], 1, 0, 2, 1);
	if(main_var->encrypt)
	{
		gtk_grid_attach (GTK_GRID (grid), label[1], 0, 1, 1, 1);
		gtk_grid_attach (GTK_GRID (grid), main_var->pwd_entry[1], 1, 1, 2, 1);
		gtk_grid_attach (GTK_GRID (grid), info_bar, 0, 2, 3, 1);
	}
	else
	{
		gtk_grid_attach (GTK_GRID (grid), info_bar, 0, 1, 3, 1);
	}

	gtk_container_add (GTK_CONTAINER (content_area), grid);
	gtk_widget_show_all (dialog);
	
	result = gtk_dialog_run (GTK_DIALOG(dialog));
	switch (result)
	{
		case GTK_RESPONSE_ACCEPT:
			if (main_var->encrypt)
			{
				ret_val = check_pwd (main_var->pwd_entry[0], main_var->pwd_entry[1]);
				if (ret_val < 0)
				{
					if (ret_val == -1)
						error_dialog ( _("Passwords are different, try again.\n"), main_var->main_window);
					else
						error_dialog ( _("Password is < 8 chars, try again\n"), main_var->main_window);
							
					gtk_widget_destroy (dialog);
					goto restart;
				}
				else
				{
					gtk_widget_hide (dialog);
					create_dialog (main_var);		
				}

			}
			else
			{
				main_var->hmac_error = FALSE;
				gtk_widget_hide (dialog);
				create_dialog (main_var);
				if (main_var->hmac_error)
				{
					gtk_widget_destroy (dialog);
					goto restart;
				}
			}
			break;
			
		case GTK_RESPONSE_REJECT:
			break;
			
		default:
			g_printerr ("Exiting...\n");
			break;
	}
	
	gtk_widget_destroy (dialog);
}


static void
hide_menu (struct main_vars *main_var)
{
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (main_var->menu)))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (main_var->menu), FALSE);
}


static void
toggle_changed_cb (	GtkToggleButton *button,
					GtkWidget *popover)
{
	gtk_widget_set_visible (popover, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button)));
}


static void
compute_hash_dialog (	GtkWidget *file_dialog,
						GtkWidget *main_window,
						const gchar *filename)
{
	gtk_widget_hide (GTK_WIDGET (file_dialog));
	
	struct hash_vars hash_var;
	gint counter, i, result;;
	
	hash_var.hash_table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	
	gsize filename_length = strlen (filename);
	
	hash_var.filename = g_malloc (filename_length + 1);
	if (hash_var.filename == NULL)
	{
		g_printerr ("Error during memory allocation\n");
		return;
	}
	g_utf8_strncpy (hash_var.filename, filename, filename_length);
	hash_var.filename[filename_length] = '\0';
	
	const gchar *label[] = {"MD5", "GOST94", "SHA-1", "SHA-256", "SHA3-256", "SHA-384", "SHA3-384", "SHA512", "SHA3-512", "WHIRLPOOL"};
	gsize label_length;
	
	GtkWidget *content_area, *grid, *dialog;
	GtkDialogFlags flags = GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT;

	PangoFontDescription *new_font = pango_font_description_new ();
	pango_font_description_set_family (new_font, "monospace");
	
	dialog = gtk_dialog_new_with_buttons ("Select Hash",
				     GTK_WINDOW (main_window),
				     flags,
				     _("Cancel"), GTK_RESPONSE_REJECT,
				     NULL);

	gtk_widget_set_size_request (dialog, 250, 150);
	
	content_area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
	
	for(i = 0; i < NUM_OF_HASH; i++)
	{
		label_length = g_utf8_strlen (label[i], -1);
		hash_var.key[i] = g_malloc (label_length + 1);
		g_utf8_strncpy (hash_var.key[i], label[i], label_length + 1);
	}
	
	for (i = 0; i < NUM_OF_HASH; i++)
	{
		hash_var.hash_check[i] = gtk_check_button_new_with_label (label[i]);
		hash_var.hash_entry[i] = gtk_entry_new ();
		gtk_editable_set_editable (GTK_EDITABLE (hash_var.hash_entry[i]), FALSE);
		gtk_widget_override_font (GTK_WIDGET (hash_var.hash_entry[i]), new_font);
	}
	
	pango_font_description_free (new_font);
	
	grid = gtk_grid_new ();
	gtk_grid_set_row_homogeneous (GTK_GRID (grid), TRUE);
	gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 5);
	
	for (counter = 0; counter < NUM_OF_HASH; counter++)
	{
		gtk_grid_attach (GTK_GRID (grid), hash_var.hash_check[counter], 0, counter, 1, 1);
		gtk_grid_attach (GTK_GRID (grid), hash_var.hash_entry[counter], 2, counter, 6, 1);
	}
	
	gtk_container_add (GTK_CONTAINER (content_area), grid);
	gtk_widget_show_all (dialog);
	
	for (i = 0; i < NUM_OF_HASH; i++)
	{
		gtk_widget_set_name (GTK_WIDGET (hash_var.hash_check[i]), bt_names[i]);
		hash_var.gth_created[i] = FALSE;
		g_signal_connect (hash_var.hash_check[i], "clicked", G_CALLBACK (create_thread), &hash_var);
	}
	
	result = gtk_dialog_run (GTK_DIALOG (dialog));
	switch (result)
	{
		case GTK_RESPONSE_REJECT:
			for (i = 0; i < NUM_OF_HASH; i++)
			{
				if(hash_var.gth_created[i])
					g_thread_join (hash_var.threads.gth[i]);
			}
				
			g_free (hash_var.filename);
			g_hash_table_destroy (hash_var.hash_table);
			gtk_widget_destroy (dialog);
			break;
	}
}


gpointer
create_thread (	GtkWidget *bt,
				gpointer user_data)
{
	
	gint i;
	struct hash_vars *hash_var = user_data;
	const gchar *name = gtk_widget_get_name (bt);
	
	for (i = 0; i < NUM_OF_HASH; i++)
	{
		if (g_strcmp0 (name, bt_names[i]) == 0)
		{
			if (g_strcmp0 (name, "BtSha256") == 0 || g_strcmp0 (name, "BtSha3_256") == 0)
				hash_var->n_bit = 256;
			else if (g_strcmp0 (name, "BtSha384") == 0 || g_strcmp0 (name, "BtSha3_384") == 0)
				hash_var->n_bit = 384;
			else if (g_strcmp0 (name, "BtSha512") == 0 || g_strcmp0 (name, "BtSha3_512") == 0)
				hash_var->n_bit = 512;
			
			hash_var->gth_created[i] = TRUE;
			hash_var->threads.gth[i] = g_thread_new (NULL, (GThreadFunc)hash_func[i], hash_var);
		}
	}
}
	
	
	
	
