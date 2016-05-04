#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gi18n.h>
#include "gtkcrypto.h"
#include "main.h"


GtkWidget
*create_popover (GtkWidget *parent, GtkPositionType pos, struct main_vars *main_var) {

	GtkWidget *popover, *box[3], *label[2], *hline[2], *vline;
	const gchar *algo[] = {"Serpent", "Twofish", "Camellia-256"};
	gint i, j;

	label[0] = gtk_label_new ( _("Cipher Algo"));
	label[1] = gtk_label_new ( _("Block Mode"));
	
	hline[0] = gtk_separator_new (GTK_ORIENTATION_HORIZONTAL);
	hline[1] = gtk_separator_new (GTK_ORIENTATION_HORIZONTAL);

	box[0] = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	box[1] = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
	box[2] = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	
	gtk_box_set_homogeneous (GTK_BOX (box[1]), FALSE);

	popover = gtk_popover_new (parent);
	gtk_popover_set_position (GTK_POPOVER (popover), pos);

	main_var->radio_button[0] = gtk_radio_button_new_with_label_from_widget (NULL, "AES-256");
	for (i=1, j=0; i<4; i++, j++)
		main_var->radio_button[i] = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON (main_var->radio_button[0]), algo[j]);
	
	main_var->radio_button[4] = gtk_radio_button_new_with_label_from_widget (NULL, "CBC");
	main_var->radio_button[5] = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON (main_var->radio_button[4]), "CTR");

	gtk_box_pack_start (GTK_BOX (box[0]), label[0], TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box[0]), hline[0], TRUE, TRUE, 0);
	for (i=0; i<4; i++)
		gtk_box_pack_start (GTK_BOX (box[0]), main_var->radio_button[i], TRUE, TRUE, 0);
	
	gtk_box_pack_start (GTK_BOX (box[2]), label[1], FALSE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box[2]), hline[1], FALSE, TRUE, 0);
	for (i=4; i<6; i++)
		gtk_box_pack_start (GTK_BOX (box[2]), main_var->radio_button[i], FALSE, TRUE, 0);
	
	vline = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
	gtk_box_pack_start (GTK_BOX(box[1]), box[0], TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box[1]), vline, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX(box[1]), box[2], FALSE, TRUE, 0);

	g_object_set(main_var->radio_button[0], "active", TRUE, NULL);
	g_object_set(main_var->radio_button[4], "active", TRUE, NULL);
	
	gtk_container_add (GTK_CONTAINER (popover), box[1]);
	gtk_container_set_border_width (GTK_CONTAINER (popover), 4);
	gtk_widget_show_all (box[1]);
	
	return popover; 
}
