#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <libnotify/notify.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "polcrypt.h"

struct _widget{
	GtkWidget *text_view;
	GtkTextBuffer *buffer;
	gchar *text;
	guchar *binaryEncText;
	guchar *binaryDecText;
	gchar *decoded_text;
	gsize totalLen;
	gsize outLen;
	gint8 action; // 1=enc, 2=dec
} Widgets;

static void enc_dec_text(struct _widget *);
static void on_button_clicked(struct _widget *);
static void close_dialog(GtkWidget *);

/* ToDo:
 * - aggiungere input pwd
 */
void insert_text(GtkWidget *clickedButton){
	GtkWidget *dialog;
	GtkWidget *scrolledwin;
	GtkWidget *box;
	GtkWidget *content_area;
	GtkWidget *okbt, *clbt;
	
	const gchar *btLabel = gtk_widget_get_name(clickedButton);
	if(g_strcmp0(btLabel, "butEnText") == 0) Widgets.action = 1;
	else Widgets.action = 2;
  
	dialog = gtk_dialog_new();
	gtk_window_set_title(GTK_WINDOW(dialog), _("Insert Text"));
	gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
	
	scrolledwin = gtk_scrolled_window_new(NULL, NULL);

	gtk_widget_set_size_request (dialog, 800, 600);

	box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
		
	Widgets.text_view = gtk_text_view_new ();
	
	gtk_box_pack_start(GTK_BOX(box), Widgets.text_view, TRUE, TRUE, 0);
	
	g_object_set (Widgets.text_view, "expand", TRUE, NULL);

	gtk_container_add (GTK_CONTAINER (scrolledwin), box);
	gtk_container_add (GTK_CONTAINER (content_area), scrolledwin);
	
	okbt = gtk_dialog_add_button(GTK_DIALOG(dialog), "OK", GTK_RESPONSE_OK);
	clbt = gtk_dialog_add_button(GTK_DIALOG(dialog), _("Cancel"), GTK_RESPONSE_OK);

	Widgets.buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (Widgets.text_view));

	gtk_text_buffer_set_text (Widgets.buffer, _("Write here your text"), -1);
    
    gtk_widget_show_all(dialog);
    
	g_signal_connect_swapped (clbt, "clicked", G_CALLBACK(close_dialog), dialog);
	g_signal_connect_swapped (okbt, "clicked", G_CALLBACK(on_button_clicked), &Widgets);
}

static void on_button_clicked (struct _widget *Widgets){
	GtkTextIter start;
	GtkTextIter end;
	
	gtk_text_buffer_get_start_iter (Widgets->buffer, &start);
	gtk_text_buffer_get_end_iter (Widgets->buffer, &end);

	Widgets->text = gtk_text_buffer_get_text (Widgets->buffer, &start, &end, FALSE);
	
	if(Widgets->action == 1){
		enc_dec_text(Widgets);

		gsize outBufLen = ((Widgets->totalLen/3+1)*4+4)+(((Widgets->totalLen/3+1)*4+4)/72+1);
		gsize outLen;
		gint state = 0, save = 0;

		gchar *encoded_text = g_malloc0(outBufLen);
		
		outLen = g_base64_encode_step(Widgets->binaryEncText, Widgets->totalLen, TRUE, encoded_text, &state, &save);
		g_base64_encode_close(TRUE, encoded_text+outLen, &state, &save);

		PangoFontDescription *newfont = pango_font_description_new();
		pango_font_description_set_family(newfont, "monospace");
		gtk_widget_override_font(GTK_WIDGET(Widgets->text_view), newfont);
		
		gtk_text_buffer_set_text (Widgets->buffer, encoded_text, -1);
		
		pango_font_description_free(newfont);

		g_free (Widgets->binaryEncText);
		g_free (encoded_text);
	}
	else{
		Widgets->binaryDecText = g_base64_decode(Widgets->text, &(Widgets->outLen));
				
		enc_dec_text(Widgets);
		
		gtk_text_buffer_set_text (Widgets->buffer, Widgets->decoded_text, -1);
		
		g_free (Widgets->binaryDecText);
		g_free (Widgets->decoded_text);
	}
	g_free (Widgets->text);
}

/* ToDo:
 * - rimuovere pwd dalla funzione, leggerla da input fornito dal main
 */
static void enc_dec_text(struct _widget *Widgets){
	gint algo = -1, mode = -1, counterForGoto = 0;
	guchar *derived_key = NULL, *crypto_key = NULL, *tmpEncBuf = NULL;
	gsize blkLength, keyLength, textLen;
		
	gcry_cipher_hd_t hd;
	guchar iv[16];
	guchar salt[32];
	
	algo = gcry_cipher_map_name("aes256");
	mode = GCRY_CIPHER_MODE_CTR;

	const gchar *inputKey = "paolo";

	blkLength = gcry_cipher_get_algo_blklen(algo);
	keyLength = gcry_cipher_get_algo_keylen(algo);	

	if(Widgets->action == 1){
		gcry_create_nonce(iv, 16);
		gcry_create_nonce(salt, 32);
	}
	else{
		memcpy(iv, Widgets->binaryDecText, 16);
		memcpy(salt, Widgets->binaryDecText+16, 32);	
	}
	
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
	
	tryAgainDerive:
	if(gcry_kdf_derive (inputKey, 5, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, 32, 150000, 64, derived_key) != 0){
		if(counterForGoto == 3){
			g_print(_("encrypt_file: Key derivation error\n"));
			gcry_free(derived_key);
			gcry_free(crypto_key);
			return;
		}
		counterForGoto += 1;
		goto tryAgainDerive;
	}
	memcpy(crypto_key, derived_key, 32);

	gcry_cipher_setkey(hd, crypto_key, keyLength);
	gcry_cipher_setiv(hd, iv, blkLength);
	
	if(Widgets->action == 1){
		Widgets->totalLen = g_utf8_strlen(Widgets->text, -1)+16+32; //aggiungo iv e salt
		Widgets->binaryEncText = g_malloc0(Widgets->totalLen);
		textLen = (Widgets->totalLen)-48;
		tmpEncBuf = g_malloc(textLen);

		gcry_cipher_encrypt(hd, tmpEncBuf, textLen, Widgets->text, textLen);
	
		memcpy(Widgets->binaryEncText, iv, 16);
		memcpy(Widgets->binaryEncText+16, salt, 32);
		memcpy(Widgets->binaryEncText+48, tmpEncBuf, textLen);
		
		g_free(tmpEncBuf);
	}
	else{
		gsize realLen = Widgets->outLen-48;
		Widgets->decoded_text = g_malloc0(realLen);
	
		gcry_cipher_decrypt(hd, Widgets->decoded_text, realLen, Widgets->binaryDecText+48, realLen);
	}
	
	gcry_cipher_close(hd);
	gcry_free(derived_key);
	gcry_free(crypto_key);
}

static void close_dialog(GtkWidget *dialog){
	gtk_widget_destroy(dialog);
}
