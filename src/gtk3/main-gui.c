#include <gtk/gtk.h>
#include <glib.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "polcrypt.h"

static void file_dialog(struct widget_t *);
static void is_enc(GtkWidget *, struct widget_t *);
static void is_dec(GtkWidget *, struct widget_t *);
static void is_hash(GtkWidget *, struct widget_t *);
static void type_pwd_enc(struct widget_t *);
static void type_pwd_dec(struct widget_t *);
static void do_enc(struct widget_t *);
static void select_hash_type(struct widget_t *);
static void activate (GtkApplication *, gpointer);
static void startup (GtkApplication *, gpointer);
static void quit (GSimpleAction *, GVariant *, gpointer);
static void about (GSimpleAction *, GVariant *, gpointer);
static void show_error(struct widget_t *, const gchar *);
gint encrypt_file_gui(struct widget_t *);
gint decrypt_file_gui(struct widget_t *);
void *compute_md5(struct hashWidget_t *);
void *compute_sha1(struct hashWidget_t *);
void *compute_sha256(struct hashWidget_t *);
void *compute_sha3_256(struct hashWidget_t *);
void *compute_sha512(struct hashWidget_t *);
void *compute_sha3_512(struct hashWidget_t *);
void *compute_whirlpool(struct hashWidget_t *);
void *compute_gostr(struct hashWidget_t *);
void *compute_stribog512(struct hashWidget_t *);

static void *threadMD5(struct hashWidget_t *);
static void *threadSHA1(struct hashWidget_t *);
static void *threadSHA256(struct hashWidget_t *);
static void *threadSHA3_256(struct hashWidget_t *);
static void *threadSHA512(struct hashWidget_t *);
static void *threadSHA3_512(struct hashWidget_t *);
static void *threadWHIRLPOOL(struct hashWidget_t *);
static void *threadGOSTR(struct hashWidget_t *);
static void *threadSTRIBOG512(struct hashWidget_t *);

struct widget_t Widget;
const gchar *icon = "/usr/share/icons/hicolor/128x128/apps/polcrypt.png";

GCRY_THREAD_OPTION_PTHREAD_IMPL;

gint main(int argc, char **argv){
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	if(!gcry_check_version(GCRYPT_MIN_VER)){
		fputs("libgcrypt min version required: 1.6.0\n", stderr);
		return -1;
	}
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALE_DIR);
	textdomain(PACKAGE);
	
	GtkApplication *app;
	gint status;
	GError *err = NULL;
	GdkPixbuf *logo = gdk_pixbuf_new_from_file(icon, &err);
	gtk_window_set_default_icon(logo);

	app = gtk_application_new ("org.gtk.polcrypt",G_APPLICATION_FLAGS_NONE);
	g_signal_connect (app, "startup", G_CALLBACK (startup), NULL);
	g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);
	status = g_application_run (G_APPLICATION (app), argc, argv);
	g_object_unref (app);
	return status;
}

static void startup (GtkApplication *application, gpointer user_data __attribute__ ((unused)))
{
	static const GActionEntry actions[] = {
		{ "about", about },
		{ "quit", quit }
	};
	
	GMenu *menu;
	
	g_action_map_add_action_entries (G_ACTION_MAP (application), actions, G_N_ELEMENTS (actions), application);
	
	menu = g_menu_new ();
	g_menu_append (menu, _("About"), "app.about");
	g_menu_append (menu, _("Quit"),  "app.quit");
	gtk_application_set_app_menu (application, G_MENU_MODEL (menu));
	g_object_unref (menu);
}

static void activate (GtkApplication *app, gpointer user_data __attribute__ ((unused)))
{
	GtkWidget *butEn, *butDe, *butHa, *grid;
	GtkWidget *label;
	GError *err = NULL;
	
	const gchar *glibVer = glib_check_version(2, 36, 0);
	if(glibVer != NULL){
		show_error(NULL, "The required version of GLib is 2.36.0 or greater.");
		return;
	}
	const gchar *gtkVer = gtk_check_version(3, 4, 0);
	if(gtkVer != NULL){
		show_error(NULL, "The required version of GTK+ is 3.4.0 or greater.");
		return;
	}	
	
	Widget.mainwin = gtk_application_window_new(app);
	gtk_window_set_application (GTK_WINDOW (Widget.mainwin), GTK_APPLICATION (app));
	gtk_window_set_position(GTK_WINDOW(Widget.mainwin), GTK_WIN_POS_CENTER);
	gtk_window_set_title(GTK_WINDOW(Widget.mainwin), "PolCrypt");
	gtk_window_set_resizable(GTK_WINDOW(Widget.mainwin), FALSE);
	gtk_window_set_icon_from_file(GTK_WINDOW(Widget.mainwin), icon, &err);
	gtk_container_set_border_width(GTK_CONTAINER(Widget.mainwin), 10);
	
	gchar welcomeBuf[40];
	sprintf(welcomeBuf, _("Welcome to PolCrypt %s"), VERSION);
	label = gtk_label_new(welcomeBuf);
	gchar *markup;
	markup = g_markup_printf_escaped ("<span foreground=\"black\" size=\"x-large\"><b>%s</b></span>", welcomeBuf); // font grassetto e large
	gtk_label_set_markup (GTK_LABEL (label), markup);
	g_free(markup);
	
	butEn = gtk_button_new_with_label(_("Encrypt File"));
	butDe = gtk_button_new_with_label(_("Decrypt File"));
	butHa = gtk_button_new_with_label(_("Compute Hash"));
	g_signal_connect(butEn, "clicked", G_CALLBACK (is_enc), &Widget);
	g_signal_connect(butDe, "clicked", G_CALLBACK (is_dec), &Widget);
	g_signal_connect(butHa, "clicked", G_CALLBACK (is_hash), &Widget);
	
	grid = gtk_grid_new();
	gtk_container_add(GTK_CONTAINER(Widget.mainwin), grid);
	gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);
	gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
	gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
	gtk_grid_set_column_spacing(GTK_GRID(grid), 5);
	
	//numero colonna, numero riga, colonne da occupare, righe da occupare. Colonne e righe sono aggiunte automaticamente
	gtk_grid_attach(GTK_GRID(grid), label, 0, 0, 5, 1);
	g_object_set (label, "margin-bottom", 12, NULL);
	gtk_grid_attach(GTK_GRID(grid), butEn, 1, 1, 3, 1);
	gtk_grid_attach(GTK_GRID(grid), butDe, 1, 2, 3, 1);
	gtk_grid_attach(GTK_GRID(grid), butHa, 1, 3, 3, 1);

	gtk_widget_show_all(Widget.mainwin);
}

static void is_enc(GtkWidget *ignored __attribute__ ((unused)), struct widget_t *Widget){
	Widget->mode = 1;
	file_dialog(Widget);
}

static void is_dec(GtkWidget *ignored __attribute__ ((unused)), struct widget_t *Widget){
	Widget->mode = 2;
	file_dialog(Widget);
}

static void is_hash(GtkWidget *ignored __attribute__ ((unused)), struct widget_t *Widget){
	Widget->mode = 3;
	file_dialog(Widget);
}

static void file_dialog(struct widget_t *Widget){
	Widget->file_dialog =  gtk_file_chooser_dialog_new(_("Choose File"), NULL, GTK_FILE_CHOOSER_ACTION_OPEN, (_("_Cancel")), GTK_RESPONSE_CANCEL, (_("_Ok")), GTK_RESPONSE_ACCEPT, NULL);
	if (gtk_dialog_run (GTK_DIALOG (Widget->file_dialog)) == GTK_RESPONSE_ACCEPT){
		Widget->filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (Widget->file_dialog));
		if(Widget->mode == 1){
			type_pwd_enc(Widget);
			g_free (Widget->filename);
		}
		else if(Widget->mode == 2){
			type_pwd_dec(Widget);
			g_free (Widget->filename);
		}
		else if(Widget->mode == 3){
			select_hash_type(Widget);
			g_free (Widget->filename);
		}
	}
	gtk_widget_destroy (Widget->file_dialog);
}

static void type_pwd_enc(struct widget_t *WidgetEnc){
	gtk_widget_hide(GTK_WIDGET(WidgetEnc->file_dialog));
	GtkWidget *content_area, *grid2, *labelPwd, *labelRetypePwd, *infoarea, *labelCombo;
   	WidgetEnc->dialog = gtk_dialog_new_with_buttons (_("Encryption Password"), NULL, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, _("_Quit"), GTK_RESPONSE_CLOSE, _("_Ok"), GTK_RESPONSE_OK, NULL);
   	content_area = gtk_dialog_get_content_area (GTK_DIALOG (WidgetEnc->dialog));
   	
   	WidgetEnc->combomenu = gtk_combo_box_text_new();
   	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(WidgetEnc->combomenu), "0", "AES-256");
   	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(WidgetEnc->combomenu), "1", "SERPENT-256");
   	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(WidgetEnc->combomenu), "2", "TWOFISH-256");
   	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(WidgetEnc->combomenu), "3", "CAMELLIA-256");
   	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(WidgetEnc->combomenu), "4", "AES+TWOFISH");
   	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(WidgetEnc->combomenu), "5", "AES+SERPENT");
   	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(WidgetEnc->combomenu), "6", "TWOFISH+SERPENT");
   	gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(WidgetEnc->combomenu), "7", "AES+SERPENT+TWOFISH");
   	
   	labelPwd = gtk_label_new(_("Type password"));
   	labelRetypePwd = gtk_label_new(_("Retype password"));
   	labelCombo = gtk_label_new(_("Select Algo"));
   	WidgetEnc->pwdEntry = gtk_entry_new();
   	WidgetEnc->pwdReEntry = gtk_entry_new();
   	gtk_entry_set_visibility(GTK_ENTRY(WidgetEnc->pwdEntry), FALSE); //input nascosto
   	gtk_entry_set_visibility(GTK_ENTRY(WidgetEnc->pwdReEntry), FALSE);
   	
   	gtk_widget_set_size_request(WidgetEnc->dialog, 150, 100); // richiedo una grandezza minima
	
   	WidgetEnc->infobar = gtk_info_bar_new();
	WidgetEnc->infolabel = gtk_label_new(_("Encrypting and deleting the file can take some minutes depending on the file size..."));
	gtk_label_set_justify(GTK_LABEL(WidgetEnc->infolabel), GTK_JUSTIFY_CENTER);
	gtk_info_bar_set_message_type(GTK_INFO_BAR(WidgetEnc->infobar), GTK_MESSAGE_INFO);
	infoarea = gtk_info_bar_get_content_area(GTK_INFO_BAR(WidgetEnc->infobar));
	gtk_container_add(GTK_CONTAINER(infoarea), WidgetEnc->infolabel);
    	
   	grid2 = gtk_grid_new();
	gtk_grid_set_column_homogeneous(GTK_GRID(grid2), TRUE); // colonne stessa larghezza
	gtk_grid_set_row_spacing(GTK_GRID(grid2), 5); // spazio fra le righe
	
	GValue marginTop = G_VALUE_INIT;
	g_value_init (&marginTop, G_TYPE_UINT);
	g_value_set_uint(&marginTop, 10);
	g_object_set_property(G_OBJECT(labelCombo), "margin-top", &marginTop);
	g_object_set_property(G_OBJECT(WidgetEnc->combomenu), "margin-top", &marginTop);

	GValue marginLeft = G_VALUE_INIT;
	g_value_init (&marginLeft, G_TYPE_UINT);
	g_value_set_uint(&marginLeft, 2);
	g_object_set_property(G_OBJECT(WidgetEnc->combomenu), "margin-left", &marginLeft);
	g_object_set_property(G_OBJECT(WidgetEnc->pwdEntry), "margin-left", &marginLeft);
	g_object_set_property(G_OBJECT(WidgetEnc->pwdReEntry), "margin-left", &marginLeft);
	
	
	gtk_grid_attach(GTK_GRID(grid2), labelCombo, 0, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), WidgetEnc->combomenu, 1, 0, 2, 1);
	gtk_grid_attach(GTK_GRID(grid2), labelPwd, 0, 1, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), WidgetEnc->pwdEntry, 1, 1, 2, 1);
	gtk_grid_attach(GTK_GRID(grid2), labelRetypePwd, 0, 2, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), WidgetEnc->pwdReEntry, 1, 2, 2, 1);
	gtk_grid_attach(GTK_GRID(grid2), WidgetEnc->infobar, 0, 3, 3, 1);

   	/* Add the grid, and show everything we've added to the dialog */
   	gtk_container_add (GTK_CONTAINER (content_area), grid2);
   	gtk_widget_show_all (WidgetEnc->dialog);
   	
   	gint result = gtk_dialog_run(GTK_DIALOG(WidgetEnc->dialog));
	switch(result){
		case GTK_RESPONSE_OK:
			do_enc(WidgetEnc);
			gtk_widget_destroy(WidgetEnc->dialog);
			if(WidgetEnc->toEnc == -1) show_error(WidgetEnc, _("Password are different, try again!"));
			break;
		case GTK_RESPONSE_CLOSE:
			gtk_widget_destroy(WidgetEnc->dialog);
			break;
	}
}

static void type_pwd_dec(struct widget_t *WidgetDec){
	gtk_widget_hide(GTK_WIDGET(WidgetDec->file_dialog));
	GtkWidget *content_area, *grid2, *label, *infoarea;
   	WidgetDec->dialog = gtk_dialog_new_with_buttons (_("Decryption Password"), NULL, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, _("_Quit"), GTK_RESPONSE_CLOSE, _("_Ok"), GTK_RESPONSE_OK, NULL);
   	content_area = gtk_dialog_get_content_area (GTK_DIALOG (WidgetDec->dialog));
   	
   	label = gtk_label_new(_("Type password"));
   	WidgetDec->pwdEntry = gtk_entry_new();
   	gtk_entry_set_visibility(GTK_ENTRY(WidgetDec->pwdEntry), FALSE); //input nascosto
   	
   	gtk_widget_set_size_request(WidgetDec->dialog, 150, 100); // richiedo una grandezza minima
   
   	WidgetDec->infobar = gtk_info_bar_new();
	WidgetDec->infolabel = gtk_label_new(_("Decrypting the file can take some minutes depending on the file size..."));
	gtk_label_set_justify(GTK_LABEL(WidgetDec->infolabel), GTK_JUSTIFY_CENTER);
	gtk_info_bar_set_message_type(GTK_INFO_BAR(WidgetDec->infobar), GTK_MESSAGE_INFO);
	infoarea = gtk_info_bar_get_content_area(GTK_INFO_BAR(WidgetDec->infobar));
	gtk_container_add(GTK_CONTAINER(infoarea), WidgetDec->infolabel);
	
	GValue marginLeft = G_VALUE_INIT;
	g_value_init (&marginLeft, G_TYPE_UINT);
	g_value_set_uint(&marginLeft, 2);
	g_object_set_property(G_OBJECT(WidgetDec->pwdEntry), "margin-left", &marginLeft);
	
	GValue marginTop = G_VALUE_INIT;
	g_value_init (&marginTop, G_TYPE_UINT);
	g_value_set_uint(&marginTop, 10);
	g_object_set_property(G_OBJECT(label), "margin-top", &marginTop);
	g_object_set_property(G_OBJECT(WidgetDec->pwdEntry), "margin-top", &marginTop);
   	
   	grid2 = gtk_grid_new();
	gtk_grid_set_column_homogeneous(GTK_GRID(grid2), TRUE); // colonne stessa larghezza
	gtk_grid_set_row_spacing(GTK_GRID(grid2), 5); // spazio fra le righe
	
	gtk_grid_attach(GTK_GRID(grid2), label, 0, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), WidgetDec->pwdEntry, 1, 0, 2, 1);
	gtk_grid_attach(GTK_GRID(grid2), WidgetDec->infobar, 0, 1, 3, 1);

   	/* Add the grid, and show everything we've added to the dialog */
   	gtk_container_add (GTK_CONTAINER (content_area), grid2);
   	gtk_widget_show_all (WidgetDec->dialog);
   	
   	gint result = gtk_dialog_run(GTK_DIALOG(WidgetDec->dialog));
	switch(result){
		case GTK_RESPONSE_OK:
			if(decrypt_file_gui(WidgetDec) == -15){
				gtk_widget_destroy(WidgetDec->dialog);
				type_pwd_dec(WidgetDec);
			}
			else gtk_widget_destroy(WidgetDec->dialog);
			break;
		case GTK_RESPONSE_CLOSE:
			gtk_widget_destroy (WidgetDec->dialog);	
			break;
	}
}

static void do_enc(struct widget_t *WidgetCheckPwd){
	WidgetCheckPwd->toEnc = 0;
	const gchar *pw1 = gtk_entry_get_text(GTK_ENTRY(WidgetCheckPwd->pwdEntry));
	const gchar *pw2 = gtk_entry_get_text(GTK_ENTRY(WidgetCheckPwd->pwdReEntry));
	
	if(g_strcmp0(pw1, pw2) != 0){
		WidgetCheckPwd->toEnc = -1;
	}

	if(WidgetCheckPwd->toEnc == 0){
		encrypt_file_gui(WidgetCheckPwd);
	}
}

static void select_hash_type(struct widget_t *WidgetHash){
	gtk_widget_hide(GTK_WIDGET(WidgetHash->file_dialog));
	struct hashWidget_t HashWidget;
	GtkWidget *content_area, *grid2;
   	WidgetHash->dialog = gtk_dialog_new_with_buttons (_("Select Hash"), NULL, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, _("_Quit"), GTK_RESPONSE_CLOSE, NULL);
   	content_area = gtk_dialog_get_content_area (GTK_DIALOG (WidgetHash->dialog));
   	   	
   	HashWidget.checkMD5 = gtk_check_button_new_with_label("MD5");
   	HashWidget.checkS1 = gtk_check_button_new_with_label("SHA-1");
   	HashWidget.checkS256 = gtk_check_button_new_with_label("SHA-256");
   	HashWidget.checkS3_256 = gtk_check_button_new_with_label("SHA3-256");
   	HashWidget.checkS512 = gtk_check_button_new_with_label("SHA-512");
   	HashWidget.checkS3_512 = gtk_check_button_new_with_label("SHA3-512");
   	HashWidget.checkWhir = gtk_check_button_new_with_label("Whirlpool");
   	HashWidget.checkGOSTR = gtk_check_button_new_with_label("GOST94");
   	HashWidget.checkSTRIBOG512 = gtk_check_button_new_with_label("STRIBOG-512");
   	
   	HashWidget.entryMD5 = gtk_entry_new();
   	HashWidget.entryS1 = gtk_entry_new();
   	HashWidget.entryS256 = gtk_entry_new();
   	HashWidget.entryS3_256 = gtk_entry_new();
   	HashWidget.entryS512 = gtk_entry_new();
   	HashWidget.entryS3_512 = gtk_entry_new();
   	HashWidget.entryWhir = gtk_entry_new();
   	HashWidget.entryGOSTR = gtk_entry_new();
   	HashWidget.entrySTRIBOG512 = gtk_entry_new();
   	
   	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryMD5), FALSE);
   	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryS1), FALSE);
   	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryS256), FALSE);
   	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryS512), FALSE);
   	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryWhir), FALSE);
   	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryGOSTR), FALSE);
   	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entrySTRIBOG512), FALSE);

   	gtk_widget_set_size_request(WidgetHash->dialog, 250, 150); // richiedo una grandezza minima
   	
   	grid2 = gtk_grid_new();
	gtk_grid_set_row_homogeneous(GTK_GRID(grid2), TRUE); // righe stessa altezza
	gtk_grid_set_column_homogeneous(GTK_GRID(grid2), TRUE); // colonne stessa larghezza
	gtk_grid_set_row_spacing(GTK_GRID(grid2), 5); // spazio fra le righe
	
	// numero colonna, numero riga, colonne da occupare, righe da occupare
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkMD5, 0, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryMD5, 2, 0, 6, 1);
	
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkS1, 0, 1, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryS1, 2, 1, 6, 1);
	
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkS256, 0, 2, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryS256, 2, 2, 6, 1);
	
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkS3_256, 0, 3, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryS3_256, 2, 3, 6, 1);
	
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkS512, 0, 4, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryS512, 2, 4, 6, 1);
	
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkS3_512, 0, 5, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryS3_512, 2, 5, 6, 1);

	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkWhir, 0, 6, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryWhir, 2, 6, 6, 1);
	
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkGOSTR, 0, 7, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryGOSTR, 2, 7, 6, 1);

	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkSTRIBOG512, 0, 8, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entrySTRIBOG512, 2, 8, 6, 1);


   	/* Add the grid, and show everything we've added to the dialog */
   	gtk_container_add (GTK_CONTAINER (content_area), grid2);
   	gtk_widget_show_all (WidgetHash->dialog);
   	
   	HashWidget.filename = malloc(strlen(WidgetHash->filename)+1);
   	strcpy(HashWidget.filename, WidgetHash->filename);
   	
   	g_signal_connect_swapped(HashWidget.checkMD5, "clicked", G_CALLBACK(threadMD5), &HashWidget);
   	g_signal_connect_swapped(HashWidget.checkS1, "clicked", G_CALLBACK(threadSHA1), &HashWidget);
   	g_signal_connect_swapped(HashWidget.checkS256, "clicked", G_CALLBACK(threadSHA256), &HashWidget);
   	g_signal_connect_swapped(HashWidget.checkS3_256, "clicked", G_CALLBACK(threadSHA3_256), &HashWidget);
   	g_signal_connect_swapped(HashWidget.checkS512, "clicked", G_CALLBACK(threadSHA512), &HashWidget);   	
   	g_signal_connect_swapped(HashWidget.checkS3_512, "clicked", G_CALLBACK(threadSHA3_512), &HashWidget);
   	g_signal_connect_swapped(HashWidget.checkWhir, "clicked", G_CALLBACK(threadWHIRLPOOL), &HashWidget);
   	g_signal_connect_swapped(HashWidget.checkGOSTR, "clicked", G_CALLBACK(threadGOSTR), &HashWidget);
   	g_signal_connect_swapped(HashWidget.checkSTRIBOG512, "clicked", G_CALLBACK(threadSTRIBOG512), &HashWidget);
   	
   	gint result = gtk_dialog_run(GTK_DIALOG(WidgetHash->dialog));
	switch(result){
		case GTK_RESPONSE_CLOSE:
			g_signal_connect_swapped (WidgetHash->dialog, "response", G_CALLBACK(gtk_widget_destroy), WidgetHash->dialog);
			gtk_widget_destroy(WidgetHash->dialog);
			break;
	}
	free(HashWidget.filename);
}

static void about (GSimpleAction *action __attribute__ ((unused)), GVariant *parameter __attribute__ ((unused)), gpointer user_data __attribute__ ((unused)))
{
        const gchar *authors[] = 
        {
                "Paolo Stivanin <info@paolostivanin.com>",
                NULL,
        };
        
        GError *error = NULL;
        GdkPixbuf *logo_about = gdk_pixbuf_new_from_file_at_size(icon, 64, 64, &error);
        
        GtkWidget *a_dialog = gtk_about_dialog_new ();
        gtk_about_dialog_set_program_name (GTK_ABOUT_DIALOG (a_dialog), "PolCrypt");
        gtk_about_dialog_set_logo(GTK_ABOUT_DIALOG(a_dialog), logo_about);
        gtk_about_dialog_set_version (GTK_ABOUT_DIALOG (a_dialog), VERSION);
        gtk_about_dialog_set_copyright (GTK_ABOUT_DIALOG (a_dialog), "Copyright (C) 2014");
        gtk_about_dialog_set_comments (GTK_ABOUT_DIALOG (a_dialog), _("Encrypt files using single or multiple encryption and compute different type of hash"));
        gtk_about_dialog_set_license(GTK_ABOUT_DIALOG(a_dialog),
"This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.\n"
"\n"
"This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.\n"
"\n"
"You should have received a copy of the GNU General Public License along with this program.\n"
"If not, see http://www.gnu.org/licenses\n"
"\n"
"PolCrypt is Copyright (C) 2014 by Paolo Stivanin.\n");
        gtk_about_dialog_set_wrap_license(GTK_ABOUT_DIALOG(a_dialog), TRUE);
        gtk_about_dialog_set_website (GTK_ABOUT_DIALOG (a_dialog), "https://github.com/polslinux/PolCrypt");
        gtk_about_dialog_set_authors (GTK_ABOUT_DIALOG (a_dialog), authors);

        gtk_dialog_run(GTK_DIALOG (a_dialog));
        gtk_widget_destroy(a_dialog);
}

static void quit (GSimpleAction *action __attribute__ ((unused)), GVariant *parameter __attribute__ ((unused)), gpointer user_data __attribute__ ((unused)))
{
   GApplication *application = user_data;
   g_application_quit (application);
}

static void show_error(struct widget_t *s_Error, const gchar *message){
	GtkWidget *dialog;
	if(s_Error != NULL){
		dialog = gtk_message_dialog_new(GTK_WINDOW(s_Error->mainwin),
			GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_MESSAGE_ERROR,
			GTK_BUTTONS_OK,
			"%s", message);
	}
	else{
		dialog = gtk_message_dialog_new(NULL,
			GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_MESSAGE_ERROR,
			GTK_BUTTONS_OK,
			"%s", message);
		gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	}		
	gtk_window_set_title(GTK_WINDOW(dialog), "Error");
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
	if(s_Error != NULL) type_pwd_enc(s_Error);
}

static void *threadMD5(struct hashWidget_t *HashWidget){
	g_thread_new("t1", (GThreadFunc)compute_md5, HashWidget);
}

static void *threadSHA1(struct hashWidget_t *HashWidget){
	g_thread_new("t2", (GThreadFunc)compute_sha1, HashWidget);
}

static void *threadSHA256(struct hashWidget_t *HashWidget){
	g_thread_new("t3", (GThreadFunc)compute_sha256, HashWidget);
}

static void *threadSHA3_256(struct hashWidget_t *HashWidget){
	g_thread_new("t4", (GThreadFunc)compute_sha3_256, HashWidget);
}

static void *threadSHA512(struct hashWidget_t *HashWidget){
	g_thread_new("t5", (GThreadFunc)compute_sha512, HashWidget);
}

static void *threadSHA3_512(struct hashWidget_t *HashWidget){
	g_thread_new("t6", (GThreadFunc)compute_sha3_512, HashWidget);
}

static void *threadWHIRLPOOL(struct hashWidget_t *HashWidget){
	g_thread_new("t7", (GThreadFunc)compute_whirlpool, HashWidget);
}

static void *threadGOSTR(struct hashWidget_t *HashWidget){
	g_thread_new("t8", (GThreadFunc)compute_gostr, HashWidget);
}

static void *threadSTRIBOG512(struct hashWidget_t *HashWidget){
	g_thread_new("t9", (GThreadFunc)compute_stribog512, HashWidget);
}
