#include <gtk/gtk.h>
#include <glib.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "polcrypt.h"


GtkWidget *do_header_and_mainwin(GtkApplication *, struct widget_t *);
static GtkWidget *create_popover_dialog(GtkWidget *, GtkPositionType, struct widget_t *);
static void toggle_changed_cb (GtkToggleButton *, GtkWidget *);
static void toggle_changed_cb2(GtkToggleButton *, gpointer data);
static void hide_menu (struct widget_t *);
static void file_dialog(struct widget_t *);
static void is_enc(GtkWidget *, struct widget_t *);
static void is_dec(GtkWidget *, struct widget_t *);
static void is_hash(GtkWidget *, struct widget_t *);
static void type_pwd_enc(struct widget_t *);
static void do_enc(struct widget_t *);
static void type_pwd_dec(struct widget_t *);
static void select_hash_type(struct widget_t *);
static void activate (GtkApplication *, gpointer);
static void startup (GtkApplication *, gpointer);
static void quit (GSimpleAction *, GVariant *, gpointer);
static void about (GSimpleAction *, GVariant *, gpointer);
static void show_error(struct widget_t *, const gchar *);

void *encrypt_file_gui(struct widget_t *);
static void *threadEnc(struct widget_t *);
void *decrypt_file_gui(struct widget_t *);
static void *threadDec(struct widget_t *);
void insert_text(GtkWidget *);

void *compute_md5(struct hashWidget_t *);
void *compute_sha1(struct hashWidget_t *);
void *compute_sha256(struct hashWidget_t *);
void *compute_sha3_256(struct hashWidget_t *);
void *compute_sha512(struct hashWidget_t *);
void *compute_sha3_512(struct hashWidget_t *);
void *compute_whirlpool(struct hashWidget_t *);
void *compute_gost94(struct hashWidget_t *);

static void *threadMD5(struct hashWidget_t *);
static void *threadSHA1(struct hashWidget_t *);
static void *threadSHA256(struct hashWidget_t *);
static void *threadSHA3_256(struct hashWidget_t *);
static void *threadSHA512(struct hashWidget_t *);
static void *threadSHA3_512(struct hashWidget_t *);
static void *threadWHIRLPOOL(struct hashWidget_t *);
static void *threadGOST94(struct hashWidget_t *);

struct thread_t{
	GThread *t;
	GThread *tenc;
}Threads;

static void activate (GtkApplication *app, gpointer user_data __attribute__ ((unused))){
	g_signal_connect(butEn, "clicked", G_CALLBACK (is_enc), &Widget);
	g_signal_connect(butDe, "clicked", G_CALLBACK (is_dec), &Widget);
	g_signal_connect(butEnText, "clicked", G_CALLBACK (insert_text), NULL);
	g_signal_connect(butDeText, "clicked", G_CALLBACK (insert_text), NULL);
	g_signal_connect(butHa, "clicked", G_CALLBACK (is_hash), &Widget);
	g_signal_connect(butQ, "clicked", G_CALLBACK (quit), app);
}


static GtkWidget *create_popover_dialog (GtkWidget *parent, GtkPositionType pos, struct widget_t *Widget){

	GtkWidget *popover, *box, *box2, *box3, *label, *labelMode, *hline1, *hline2;

	label = gtk_label_new(_("Cipher Algo"));
	labelMode = gtk_label_new(_("Cipher Mode"));
	hline1 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
	hline2 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);

	box2 = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
	box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	box3 = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	gtk_box_set_homogeneous (GTK_BOX (box2), FALSE);

	popover = gtk_popover_new(parent);
	gtk_popover_set_position (GTK_POPOVER (popover), pos);

	Widget->r0_1 = gtk_radio_button_new_with_label_from_widget(NULL, "AES-256");
	Widget->r0_2 = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(Widget->r0_1), "Serpent");
	Widget->r0_3 = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(Widget->r0_1), "Twofish");
	Widget->r0_4 = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(Widget->r0_1), "Camellia-256");
	
	Widget->r1_1 = gtk_radio_button_new_with_label_from_widget(NULL, "CBC");
	Widget->r1_2 = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(Widget->r1_1), "CTR");


	gtk_box_pack_start (GTK_BOX (box), label, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box), hline1, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box), Widget->r0_1, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box), Widget->r0_2, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box), Widget->r0_3, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box), Widget->r0_4, TRUE, TRUE, 0);
	
	gtk_box_pack_start (GTK_BOX (box3), labelMode, FALSE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box3), hline2, FALSE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box3), Widget->r1_1, FALSE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box3), Widget->r1_2, FALSE, TRUE, 0);
	
	GtkWidget *vline = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
	gtk_box_pack_start( GTK_BOX(box2), box, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box2), vline, TRUE, TRUE, 0);
	gtk_box_pack_start( GTK_BOX(box2), box3, FALSE, TRUE, 0);

	g_object_set(Widget->r0_1, "active", TRUE, NULL);
	g_object_set(Widget->r1_1, "active", TRUE, NULL);

	gtk_container_add (GTK_CONTAINER (popover), box2);
	gtk_container_set_border_width (GTK_CONTAINER (popover), 4);
	gtk_widget_show_all (box2);
	
	return popover; 
}

static void toggle_changed_cb (GtkToggleButton *button, GtkWidget *popover){
	gtk_widget_set_visible (popover, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button)));
}
static void toggle_changed_cb2 (GtkToggleButton *bt, gpointer data __attribute__ ((unused))){
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(bt), FALSE);
}

static void hide_menu(struct widget_t *Widget){
	if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(Widget->menu)))
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(Widget->menu), FALSE);
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
	Widget->file_dialog =  gtk_file_chooser_dialog_new(_("Choose File"), NULL, GTK_FILE_CHOOSER_ACTION_OPEN, _("_Close"), GTK_RESPONSE_CANCEL, _("_Open"), GTK_RESPONSE_ACCEPT, NULL);
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
	GtkWidget *content_area, *grid2, *labelPwd, *labelRetypePwd, *infoarea;
	GtkWidget *header, *box, *image, *popover;
	GIcon *icon;
	
	header = gtk_header_bar_new ();
	gtk_header_bar_set_show_close_button (GTK_HEADER_BAR (header), FALSE);
	gtk_header_bar_set_title (GTK_HEADER_BAR (header), _("Encryption Password"));
	gtk_header_bar_set_has_subtitle (GTK_HEADER_BAR (header), FALSE);
	box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_style_context_add_class (gtk_widget_get_style_context (box), "linked");
	icon = g_themed_icon_new ("emblem-system-symbolic");
	image = gtk_image_new_from_gicon (icon, GTK_ICON_SIZE_BUTTON);
	g_object_unref(icon);
	
	WidgetEnc->menu = gtk_toggle_button_new();
	gtk_container_add(GTK_CONTAINER(WidgetEnc->menu), image);
	gtk_widget_set_tooltip_text(GTK_WIDGET(WidgetEnc->menu), _("Settings"));
	
	popover = create_popover_dialog(WidgetEnc->menu, GTK_POS_TOP, WidgetEnc);
	gtk_popover_set_modal (GTK_POPOVER (popover), TRUE);
	g_signal_connect (WidgetEnc->menu, "toggled", G_CALLBACK (toggle_changed_cb), popover);
	
	gtk_header_bar_pack_start(GTK_HEADER_BAR (header), GTK_WIDGET(WidgetEnc->menu));

	GtkDialogFlags flags = GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT;
	WidgetEnc->dialog = gtk_dialog_new_with_buttons (NULL, NULL, flags, _("_OK"), GTK_RESPONSE_OK, _("_Cancel"), GTK_RESPONSE_CLOSE, NULL);
	content_area = gtk_dialog_get_content_area (GTK_DIALOG (WidgetEnc->dialog));
	gtk_window_set_titlebar (GTK_WINDOW (WidgetEnc->dialog), header);
	gtk_widget_add_events(GTK_WIDGET(WidgetEnc->dialog), GDK_BUTTON_PRESS_MASK);
	g_signal_connect_swapped(WidgetEnc->dialog, "button-press-event", G_CALLBACK(hide_menu), WidgetEnc);
	
	labelPwd = gtk_label_new(_("Type password"));
	labelRetypePwd = gtk_label_new(_("Retype password"));
	WidgetEnc->pwdEntry = gtk_entry_new();
	WidgetEnc->pwdReEntry = gtk_entry_new();
	gtk_entry_set_visibility(GTK_ENTRY(WidgetEnc->pwdEntry), FALSE);
	gtk_entry_set_visibility(GTK_ENTRY(WidgetEnc->pwdReEntry), FALSE);

	gtk_widget_set_size_request(WidgetEnc->dialog, 150, 100);

	WidgetEnc->infobar = gtk_info_bar_new();
	WidgetEnc->infolabel = gtk_label_new(_("Encrypting and deleting the file can take some minutes depending on the file size..."));
	gtk_label_set_justify(GTK_LABEL(WidgetEnc->infolabel), GTK_JUSTIFY_CENTER);
	gtk_info_bar_set_message_type(GTK_INFO_BAR(WidgetEnc->infobar), GTK_MESSAGE_INFO);
	infoarea = gtk_info_bar_get_content_area(GTK_INFO_BAR(WidgetEnc->infobar));
	gtk_container_add(GTK_CONTAINER(infoarea), WidgetEnc->infolabel);

	grid2 = gtk_grid_new();
	gtk_grid_set_column_homogeneous(GTK_GRID(grid2), TRUE);
	gtk_grid_set_row_spacing(GTK_GRID(grid2), 5);

	GValue marginLeft = G_VALUE_INIT;
	g_value_init (&marginLeft, G_TYPE_UINT);
	g_value_set_uint(&marginLeft, 2);
	g_object_set_property(G_OBJECT(WidgetEnc->pwdEntry), "margin-left", &marginLeft);
	g_object_set_property(G_OBJECT(WidgetEnc->pwdReEntry), "margin-left", &marginLeft);

	gtk_grid_attach(GTK_GRID(grid2), labelPwd, 0, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), WidgetEnc->pwdEntry, 1, 0, 2, 1);
	gtk_grid_attach(GTK_GRID(grid2), labelRetypePwd, 0, 1, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), WidgetEnc->pwdReEntry, 1, 1, 2, 1);
	gtk_grid_attach(GTK_GRID(grid2), WidgetEnc->infobar, 0, 2, 3, 1);

	gtk_container_add (GTK_CONTAINER (content_area), grid2);
	gtk_widget_show_all (WidgetEnc->dialog);

	gint result = gtk_dialog_run(GTK_DIALOG(WidgetEnc->dialog));
	switch(result){
		case GTK_RESPONSE_OK:
			do_enc(WidgetEnc);
			gtk_widget_destroy(WidgetEnc->dialog);
			if(WidgetEnc->toEnc == -1) show_error(WidgetEnc, _("Password are different, try again!"));
			if(WidgetEnc->toEnc == -2) show_error(WidgetEnc, _("Your password is too short (less than 8 chars)"));
			break;
		case GTK_RESPONSE_CLOSE:
			gtk_widget_destroy(WidgetEnc->dialog);
			break;
	}
}

static void type_pwd_dec(struct widget_t *WidgetDec){
	gtk_widget_hide(GTK_WIDGET(WidgetDec->file_dialog));
	GtkWidget *content_area, *grid2, *label, *infoarea;
	WidgetDec->dialog = gtk_dialog_new_with_buttons (_("Decryption Password"), GTK_WINDOW(WidgetDec->mainwin), GTK_DIALOG_DESTROY_WITH_PARENT, _("_Cancel"), GTK_RESPONSE_CANCEL, _("_OK"), GTK_RESPONSE_OK, NULL);
	content_area = gtk_dialog_get_content_area (GTK_DIALOG (WidgetDec->dialog));

	label = gtk_label_new(_("Type password"));
	WidgetDec->pwdEntry = gtk_entry_new();
	gtk_entry_set_visibility(GTK_ENTRY(WidgetDec->pwdEntry), FALSE);

	gtk_widget_set_size_request(WidgetDec->dialog, 150, 100);

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
	gtk_grid_set_column_homogeneous(GTK_GRID(grid2), TRUE);
	gtk_grid_set_row_spacing(GTK_GRID(grid2), 5);

	gtk_grid_attach(GTK_GRID(grid2), label, 0, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), WidgetDec->pwdEntry, 1, 0, 2, 1);
	gtk_grid_attach(GTK_GRID(grid2), WidgetDec->infobar, 0, 1, 3, 1);

	gtk_container_add (GTK_CONTAINER (content_area), grid2);
	gtk_widget_show_all (WidgetDec->dialog);

	gint result = gtk_dialog_run(GTK_DIALOG(WidgetDec->dialog));
	switch(result){
		case GTK_RESPONSE_OK:
			threadDec(WidgetDec);
			gtk_widget_destroy(WidgetDec->dialog);
			break;
		case GTK_RESPONSE_CANCEL:
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
	else if(g_utf8_strlen(pw1, -1) < 8){
		WidgetCheckPwd->toEnc = -2;
	}

	if(WidgetCheckPwd->toEnc == 0){
		threadEnc(WidgetCheckPwd);
	}
}

static void *threadEnc(struct widget_t *Widget){
	Threads.tenc = g_thread_new("t_enc", (GThreadFunc)encrypt_file_gui, Widget);
}

static void *threadDec(struct widget_t *Widget){
	Threads.t = g_thread_new("t_dec", (GThreadFunc)decrypt_file_gui, Widget);
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

	HashWidget.entryMD5 = gtk_entry_new();
	HashWidget.entryS1 = gtk_entry_new();
	HashWidget.entryS256 = gtk_entry_new();
	HashWidget.entryS3_256 = gtk_entry_new();
	HashWidget.entryS512 = gtk_entry_new();
	HashWidget.entryS3_512 = gtk_entry_new();
	HashWidget.entryWhir = gtk_entry_new();
	HashWidget.entryGOSTR = gtk_entry_new();

	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryMD5), FALSE);
	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryS1), FALSE);
	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryS256), FALSE);
	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryS3_256), FALSE);
	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryS512), FALSE);
	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryS3_512), FALSE);
	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryWhir), FALSE);
	gtk_editable_set_editable(GTK_EDITABLE(HashWidget.entryGOSTR), FALSE);
	
	PangoFontDescription *newfont = pango_font_description_new();
	pango_font_description_set_family(newfont, "monospace");
	gtk_widget_override_font(GTK_WIDGET(HashWidget.entryMD5), newfont);
	gtk_widget_override_font(GTK_WIDGET(HashWidget.entryS1), newfont);
	gtk_widget_override_font(GTK_WIDGET(HashWidget.entryMD5), newfont);
	gtk_widget_override_font(GTK_WIDGET(HashWidget.entryS256), newfont);
	gtk_widget_override_font(GTK_WIDGET(HashWidget.entryS3_256), newfont);
	gtk_widget_override_font(GTK_WIDGET(HashWidget.entryS512), newfont);
	gtk_widget_override_font(GTK_WIDGET(HashWidget.entryS3_512), newfont);
	gtk_widget_override_font(GTK_WIDGET(HashWidget.entryWhir), newfont);
	gtk_widget_override_font(GTK_WIDGET(HashWidget.entryGOSTR), newfont);
	pango_font_description_free(newfont);

	gtk_widget_set_size_request(WidgetHash->dialog, 250, 150);

	grid2 = gtk_grid_new();
	gtk_grid_set_row_homogeneous(GTK_GRID(grid2), TRUE);
	gtk_grid_set_column_homogeneous(GTK_GRID(grid2), TRUE);
	gtk_grid_set_row_spacing(GTK_GRID(grid2), 5);

	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkMD5, 0, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryMD5, 2, 0, 6, 1);

	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkGOSTR, 0, 1, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryGOSTR, 2, 1, 6, 1);

	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkS1, 0, 2, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryS1, 2, 2, 6, 1);

	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkS256, 0, 3, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryS256, 2, 3, 6, 1);

	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkS3_256, 0, 4, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryS3_256, 2, 4, 6, 1);

	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkS512, 0, 5, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryS512, 2, 5, 6, 1);

	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkS3_512, 0, 6, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryS3_512, 2, 6, 6, 1);

	gtk_grid_attach(GTK_GRID(grid2), HashWidget.checkWhir, 0, 7, 1, 1);
	gtk_grid_attach(GTK_GRID(grid2), HashWidget.entryWhir, 2, 7, 6, 1);

	gtk_container_add (GTK_CONTAINER (content_area), grid2);
	gtk_widget_show_all (WidgetHash->dialog);

	HashWidget.filename = malloc(g_utf8_strlen(WidgetHash->filename, -1)+1);
	g_utf8_strncpy(HashWidget.filename, WidgetHash->filename, g_utf8_strlen(WidgetHash->filename, -1));

	g_signal_connect_swapped(HashWidget.checkMD5, "clicked", G_CALLBACK(threadMD5), &HashWidget);
	g_signal_connect_swapped(HashWidget.checkS1, "clicked", G_CALLBACK(threadSHA1), &HashWidget);
	g_signal_connect_swapped(HashWidget.checkS256, "clicked", G_CALLBACK(threadSHA256), &HashWidget);
	g_signal_connect_swapped(HashWidget.checkS3_256, "clicked", G_CALLBACK(threadSHA3_256), &HashWidget);
	g_signal_connect_swapped(HashWidget.checkS512, "clicked", G_CALLBACK(threadSHA512), &HashWidget);
	g_signal_connect_swapped(HashWidget.checkS3_512, "clicked", G_CALLBACK(threadSHA3_512), &HashWidget);
	g_signal_connect_swapped(HashWidget.checkWhir, "clicked", G_CALLBACK(threadWHIRLPOOL), &HashWidget);
	g_signal_connect_swapped(HashWidget.checkGOSTR, "clicked", G_CALLBACK(threadGOST94), &HashWidget);

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
        GdkPixbuf *logo_about = gdk_pixbuf_new_from_file_at_size(my_icon, 64, 64, &error);

        GtkWidget *a_dialog = gtk_about_dialog_new ();
        gtk_about_dialog_set_program_name (GTK_ABOUT_DIALOG (a_dialog), "PolCrypt");
        gtk_about_dialog_set_logo(GTK_ABOUT_DIALOG(a_dialog), logo_about);
        gtk_about_dialog_set_version (GTK_ABOUT_DIALOG (a_dialog), VERSION);
        gtk_about_dialog_set_copyright (GTK_ABOUT_DIALOG (a_dialog), "Copyright (C) 2014");
        gtk_about_dialog_set_comments (GTK_ABOUT_DIALOG (a_dialog), _("Encrypt and decrypt a file using different cipher algo and different ciper mode or compute its hash using different hash algo"));
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
        gtk_about_dialog_set_website (GTK_ABOUT_DIALOG (a_dialog), "https://www.paolostivanin.com");
        gtk_about_dialog_set_authors (GTK_ABOUT_DIALOG (a_dialog), authors);

        gtk_dialog_run(GTK_DIALOG (a_dialog));
        gtk_widget_destroy(a_dialog);
}

static void quit (GSimpleAction *action __attribute__ ((unused)), GVariant *parameter __attribute__ ((unused)), gpointer user_data __attribute__ ((unused))){
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
	gtk_window_set_title(GTK_WINDOW(dialog), _("Error"));
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

static void *threadGOST94(struct hashWidget_t *HashWidget){
	g_thread_new("t8", (GThreadFunc)compute_gost94, HashWidget);
}
