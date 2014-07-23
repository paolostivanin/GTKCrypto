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
