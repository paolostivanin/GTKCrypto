#include <gtk/gtk.h>
#include <glib.h>
#include "polcrypt.h"

//cc -Wall -Wextra -Wformat-security -O2 `pkg-config --cflags --libs gtk+-3.0`

static void about_clicked(GtkWidget *, gpointer);
static void file_dialog(struct info *);
static void is_enc(GtkWidget *, struct info *);
static void is_dec(GtkWidget *, struct info *);
static void is_hash(GtkWidget *, struct info *);
static void encrypt_file_gui(struct info *);
static int do_enc(struct info *);

int main(int argc, char **argv){
	GtkWidget *butEn, *butDe, *butHa, *butAb, *grid;
	GtkWidget *label;
	struct info s_Info;
	
	gtk_init(&argc, &argv);
	
	s_Info.mainwin = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_position(GTK_WINDOW(s_Info.mainwin), GTK_WIN_POS_CENTER);
	gtk_window_set_title(GTK_WINDOW(s_Info.mainwin), "PolCrypt");
	gtk_window_set_resizable(GTK_WINDOW(s_Info.mainwin), FALSE);
	g_signal_connect(s_Info.mainwin, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	gtk_container_set_border_width(GTK_CONTAINER(s_Info.mainwin), 10);
	
	const gchar *str = "Welcome to PolCrypt (v2.0-alpha1)";
	label = gtk_label_new(str);
	char *markup;
	markup = g_markup_printf_escaped ("<span foreground=\"black\" size=\"x-large\"><b>%s</b></span>", str); // font grassetto e large
	gtk_label_set_markup (GTK_LABEL (label), markup);
	
	butEn = gtk_button_new_with_label("Encrypt File");
	butDe = gtk_button_new_with_label("Decrypt File");
	butHa = gtk_button_new_with_label("Compute Hash");
	butAb = gtk_button_new_with_label("About");
	g_signal_connect(butEn, "clicked", G_CALLBACK (is_enc), &s_Info);
	g_signal_connect(butDe, "clicked", G_CALLBACK (is_dec), &s_Info);
	g_signal_connect(butHa, "clicked", G_CALLBACK (is_hash), &s_Info);
	g_signal_connect(butAb, "clicked", G_CALLBACK (about_clicked), NULL);
	
	grid = gtk_grid_new();
	gtk_container_add(GTK_CONTAINER(s_Info.mainwin), grid);
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
	gtk_grid_attach(GTK_GRID(grid), butAb, 1, 4, 3, 1);

	gtk_widget_show_all(s_Info.mainwin);
	
	gtk_main();

	return 0;
}

static void is_enc(GtkWidget *ignored __attribute__ ((unused)), struct info *s_Info){
	s_Info->mode = 1;
	file_dialog(s_Info);
}

static void is_dec(GtkWidget *ignored __attribute__ ((unused)), struct info *s_Info){
	s_Info->mode = 2;
	file_dialog(s_Info);
}

static void is_hash(GtkWidget *ignored __attribute__ ((unused)), struct info *s_Info){
	s_Info->mode = 3;
	file_dialog(s_Info);
}

static void file_dialog(struct info *s_Info){
	GtkWidget *file_dialog;
	file_dialog =  gtk_file_chooser_dialog_new("prova", GTK_WINDOW(s_Info->mainwin), GTK_FILE_CHOOSER_ACTION_OPEN, ("_Cancel"), GTK_RESPONSE_CANCEL, ("_Ok"), GTK_RESPONSE_ACCEPT, NULL);
	if (gtk_dialog_run (GTK_DIALOG (file_dialog)) == GTK_RESPONSE_ACCEPT){
		s_Info->filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (file_dialog));
		if(s_Info->mode == 1){
			encrypt_file_gui(s_Info);
		}
		/*else if(s_Info->mode == 2){
			decrypt_file_gui(filename, mainwin);
		}
		else if(s_Info->mode == 3){
			hash_file_gui(filename, mainwin);
		}*/
    	g_free (s_Info->filename);
	}
	gtk_widget_destroy (file_dialog);
}

static void encrypt_file_gui(struct info *s_InfoEnc){
	GtkWidget *content_area, *grid2, *label, *labelAgain;
   	s_InfoEnc->dialog = gtk_dialog_new_with_buttons ("Password", NULL, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, "_Quit", GTK_RESPONSE_CLOSE, "_Ok", GTK_RESPONSE_OK, NULL);
   	content_area = gtk_dialog_get_content_area (GTK_DIALOG (s_InfoEnc->dialog));
   	
   	label = gtk_label_new("Type password");
   	labelAgain = gtk_label_new("Retype password");
   	s_InfoEnc->pwdEntry = gtk_entry_new();
   	s_InfoEnc->pwdReEntry = gtk_entry_new();
   	gtk_entry_set_visibility(GTK_ENTRY(s_InfoEnc->pwdEntry), FALSE); //input nascosto
   	gtk_entry_set_visibility(GTK_ENTRY(s_InfoEnc->pwdReEntry), FALSE);

   	gtk_widget_set_size_request(s_InfoEnc->dialog, 150, 100); // richiedo una grandezza minima
   	
   	grid2 = gtk_grid_new();
	gtk_grid_set_row_homogeneous(GTK_GRID(grid2), TRUE); // righe stessa altezza
	gtk_grid_set_column_homogeneous(GTK_GRID(grid2), TRUE); // colonne stessa larghezza
	gtk_grid_set_row_spacing(GTK_GRID(grid2), 5); // spazio fra le righe
	
	gtk_grid_attach(GTK_GRID(grid2), label, 0, 0, 3, 1);
	gtk_grid_attach(GTK_GRID(grid2), s_InfoEnc->pwdEntry, 0, 1, 3, 1);
	gtk_grid_attach(GTK_GRID(grid2), labelAgain, 0, 2, 3, 1);
	gtk_grid_attach(GTK_GRID(grid2), s_InfoEnc->pwdReEntry, 0, 3, 3, 1);		

   	/* Add the grid, and show everything we've added to the dialog */
   	gtk_container_add (GTK_CONTAINER (content_area), grid2);
   	gtk_widget_show_all (s_InfoEnc->dialog);
   	
   	s_InfoEnc->isSignalActivate = 0;
   	g_signal_connect_swapped(G_OBJECT(s_InfoEnc->pwdReEntry), "activate", G_CALLBACK(do_enc), s_InfoEnc);
   	gint result = gtk_dialog_run(GTK_DIALOG(s_InfoEnc->dialog));
	switch(result){
		case GTK_RESPONSE_OK:
			s_InfoEnc->isSignalActivate = -1;
			do_enc(s_InfoEnc);
			gtk_widget_destroy(s_InfoEnc->dialog);
			break;
		case GTK_RESPONSE_CLOSE:
			g_signal_connect_swapped (s_InfoEnc->dialog, "response", G_CALLBACK(gtk_widget_destroy), s_InfoEnc->dialog);
			gtk_widget_destroy (s_InfoEnc->dialog);	
			break;
	}
}

static int do_enc(struct info *s_InfoCheckPwd){
	const gchar *pw1 = gtk_entry_get_text(GTK_ENTRY(s_InfoCheckPwd->pwdEntry));
	const gchar *pw2 = gtk_entry_get_text(GTK_ENTRY(s_InfoCheckPwd->pwdReEntry));
	if(g_strcmp0(pw1, pw2) != 0){
		g_print("pwd diverse\n");
		return -1;
	}
	if(s_InfoCheckPwd->isSignalActivate == 0) gtk_widget_destroy (GTK_WIDGET(s_InfoCheckPwd->dialog));
	//QUA CIFRO IL FILE
	g_print("ok\n");
	return 0;
}

static void about_clicked(GtkWidget *a_dialog, gpointer data __attribute__ ((unused))){

        const gchar *authors[] = /* Qui definisco gli autori*/
        {
                "Paolo Stivanin",
                NULL,
        };

        a_dialog = gtk_about_dialog_new ();
        gtk_about_dialog_set_program_name (GTK_ABOUT_DIALOG (a_dialog), "PolCrypt");
        gtk_about_dialog_set_version (GTK_ABOUT_DIALOG (a_dialog), "2.0-alpha1");
        gtk_about_dialog_set_copyright (GTK_ABOUT_DIALOG (a_dialog), "Copyright (C) 2014");
        gtk_about_dialog_set_comments (GTK_ABOUT_DIALOG (a_dialog), "You can choose both to encrypt and decrypt file using AES-256 CBC with HMAC-SHA512 for message authentication or to compute file hashes");
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

        gtk_dialog_run(GTK_DIALOG (a_dialog)); /* Avvio il dialog a_dialog */
        gtk_widget_destroy(a_dialog); /* Alla pressione del pulsante chiudi il widget viene chiuso */
}
