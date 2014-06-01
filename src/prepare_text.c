#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <libnotify/notify.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "polcrypt.h"

#define MAX_BUF 1024


struct _widget{
	GtkTextBuffer *buffer;
	GtkTextBuffer *buffer_2;
	gchar *text;
	guchar *binaryEncText;
	gsize totalLen;
};

struct _widget Widgets;

static void encrypt_text(struct _widget *);

// remember to set a MAX BUFFER (eg 5 MiB)

static void on_button_clicked (struct _widget *Widgets){
	GtkTextIter start;
	GtkTextIter end;
	
	/* Obtain iters for the start and end of points of the buffer */
	gtk_text_buffer_get_start_iter (Widgets->buffer, &start);
	gtk_text_buffer_get_end_iter (Widgets->buffer, &end);

	/* Get the entire buffer text. */
	Widgets->text = gtk_text_buffer_get_text (Widgets->buffer, &start, &end, FALSE);
	encrypt_text(Widgets);
	gchar *encoded_text = g_base64_encode(Widgets->binaryEncText, Widgets->totalLen);
	
	g_print("%s\n", encoded_text);

	g_free (Widgets->text);
	g_free (Widgets->binaryEncText);
	g_free (encoded_text);
}

gint prepare_text(struct widget_t *Widget){
	GtkWidget *dialog;
	GtkWidget *box;
	GtkWidget *text_view;
	GtkWidget *content_area;
  
	dialog = gtk_dialog_new_with_buttons ("Text", NULL,
										GTK_DIALOG_MODAL,
										"_OK", GTK_RESPONSE_OK, _("_Cancel"), GTK_RESPONSE_CANCEL,
										NULL);
	content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));

	gtk_widget_set_size_request (dialog, 600, 400);

	box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	
	text_view = gtk_text_view_new ();
	
	gtk_box_pack_start(GTK_BOX(box), text_view, TRUE, TRUE, 0);
	
	g_object_set (text_view, "expand", TRUE, NULL);
	
	gtk_container_add (GTK_CONTAINER (content_area), box);

	/* Obtaining the buffer associated with the widget. */
	Widgets.buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (text_view));

	/* Set the default buffer text. */ 
	gtk_text_buffer_set_text (Widgets.buffer, _("Write here your text"), -1);
    
    gtk_widget_show_all(dialog);
    
	gint result = gtk_dialog_run(GTK_DIALOG(dialog));
	switch(result){
		case GTK_RESPONSE_CANCEL:
			g_signal_connect_swapped (dialog, "response", G_CALLBACK(gtk_widget_destroy), NULL);
			break;
		case GTK_RESPONSE_OK:
			on_button_clicked(&Widgets);
			break;
	}
	gtk_widget_destroy(dialog);

	return 0;
}

static void encrypt_text(struct _widget *Widgets){
	gint algo = -1, mode = -1, counterForGoto = 0;
	guchar *derived_key = NULL, *crypto_key = NULL, *mac_key = NULL, *tmpEncBuf = NULL;
	gsize blkLength, keyLength, textLen;
		
	gcry_cipher_hd_t hd;
	guchar iv[16];
	guchar salt[32];
	
	algo = gcry_cipher_map_name("aes256");
	mode = GCRY_CIPHER_MODE_CTR;

	const gchar *inputKey = "paolo";

	blkLength = gcry_cipher_get_algo_blklen(algo);
	keyLength = gcry_cipher_get_algo_keylen(algo);	

	gcry_create_nonce(iv, 16);
	gcry_create_nonce(salt, 32);
	
	gcry_cipher_open(&hd, algo, mode, 0);
	
	if((derived_key = gcry_malloc_secure(64)) == NULL){
		g_print(_("encrypt_file: gcry_malloc_secure failed (derived)\n"));
		return;
	}
	
	if((crypto_key = gcry_malloc_secure(32)) == NULL){
		g_print(_("encrypt_file: gcry_malloc_secure failed (crypto)\n"));
		gcry_free(derived_key);
		return;
	}
	
	if((mac_key = gcry_malloc_secure(32)) == NULL){
		g_print(_("encrypt_file: gcry_malloc_secure failed (mac)\n"));
		gcry_free(crypto_key);
		gcry_free(derived_key);
		return;
	}

	tryAgainDerive:
	if(gcry_kdf_derive (inputKey, 5, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, 32, 150000, 64, derived_key) != 0){
		if(counterForGoto == 3){
			g_print(_("encrypt_file: Key derivation error\n"));
			gcry_free(derived_key);
			gcry_free(crypto_key);
			gcry_free(mac_key);
			return;
		}
		counterForGoto += 1;
		goto tryAgainDerive;
	}
	memcpy(crypto_key, derived_key, 32);
	memcpy(mac_key, derived_key + 32, 32);

	gcry_cipher_setkey(hd, crypto_key, keyLength);
	gcry_cipher_setiv(hd, iv, blkLength);
	
	Widgets->totalLen = g_utf8_strlen(Widgets->text, -1)+16+32; //aggiungo iv e salt
	Widgets->binaryEncText = g_malloc0(Widgets->totalLen);
	textLen = (Widgets->totalLen)-48;
	tmpEncBuf = g_malloc(textLen);

	gcry_cipher_encrypt(hd, tmpEncBuf, textLen, Widgets->text, textLen);
	
	memcpy(Widgets->binaryEncText, iv, 16);
	memcpy(Widgets->binaryEncText+16, salt, 32);
	memcpy(Widgets->binaryEncText+48, tmpEncBuf, textLen);
		
	gcry_cipher_close(hd);
	gcry_free(derived_key);
	gcry_free(crypto_key);
	gcry_free(mac_key);
	g_free(tmpEncBuf);
}
