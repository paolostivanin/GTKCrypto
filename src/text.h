#ifndef TEXT_H_INCLUDED
#define TEXT_H_INCLUDED

#include <glib.h>
#include <gtk/gtk.h>

gint check_b64 (const gchar *);


struct text_vars
{
	GtkWidget *dialog;
	GtkWidget *text_view;
	GtkWidget *pwd[2];	
	GtkTextBuffer *buffer;
	gchar *text;
	guchar *crypt_text;
	gchar *decoded_text;
	gsize total_length;
	gsize out_length;
	gsize real_len;
	gint8 action;
};
extern struct text_vars text_var;

#endif
