#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <libnotify/notify.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "polcrypt.h"


struct textWidget_t TextWidget;

static void prepare_text (struct textWidget_t *);
static void crypt_text (struct textWidget_t *);
gint check_pwd (struct textWidget_t *);
static void show_error (const gchar *);

void
text_dialog (GtkWidget *clickedButton)
{	
	GtkWidget *dialog;
	GtkWidget *contentArea;
	GtkWidget *scrolledWin;
	GtkWidget *box;
	GtkWidget *button[2];
		
	const gchar *btLabel = gtk_widget_get_name (clickedButton);
	if (g_strcmp0 (btLabel, "butEnTxt") == 0)
		TextWidget.action = 0;
	else
		TextWidget.action = 1;
		
	dialog = gtk_dialog_new ();
	gtk_window_set_title (GTK_WINDOW (dialog), _("Insert Text"));
	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);
	contentArea = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
	
	scrolledWin = gtk_scrolled_window_new (NULL, NULL);
	
	box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);

	gtk_widget_set_size_request (dialog, 800, 600);
	
	TextWidget.pwd[0] = gtk_entry_new ();
	TextWidget.pwd[1] = gtk_entry_new ();
	
	gtk_entry_set_visibility (GTK_ENTRY (TextWidget.pwd[0]), FALSE);
	gtk_entry_set_visibility (GTK_ENTRY (TextWidget.pwd[1]), FALSE);
	
	gtk_entry_set_placeholder_text (GTK_ENTRY (TextWidget.pwd[0]), _("Type Password"));
	gtk_entry_set_placeholder_text (GTK_ENTRY (TextWidget.pwd[1]), _("Retype Password"));
		
	TextWidget.textView = gtk_text_view_new ();
	gtk_container_add (GTK_CONTAINER (scrolledWin), TextWidget.textView);
	
	PangoFontDescription *newFont = pango_font_description_new ();
	pango_font_description_set_family (newFont, "monospace");
	gtk_widget_override_font (GTK_WIDGET (TextWidget.textView), newFont);
	pango_font_description_free (newFont);
	
	gtk_box_pack_start (GTK_BOX(box), TextWidget.pwd[0], TRUE, TRUE, 0);
	if (!TextWidget.action)
		gtk_box_pack_start (GTK_BOX (box), TextWidget.pwd[1], TRUE, TRUE, 0);
	
	g_object_set (TextWidget.textView, "expand", TRUE, NULL);
	
	gtk_container_add (GTK_CONTAINER (contentArea), scrolledWin);
	gtk_container_add (GTK_CONTAINER (contentArea), box);
	
	button[0] = gtk_dialog_add_button (GTK_DIALOG (dialog), _("Cancel"), GTK_RESPONSE_CANCEL);
	button[1] = gtk_dialog_add_button (GTK_DIALOG (dialog), _("OK"), GTK_RESPONSE_OK);
	
	gtk_widget_set_name (GTK_WIDGET (button[0]), "clbt");
	gtk_widget_set_name (GTK_WIDGET (button[1]), "okbt");
		
	TextWidget.buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (TextWidget.textView));

	gtk_text_buffer_set_text (TextWidget.buffer, _("Write here your text"), -1);
    
	gtk_widget_show_all (dialog);
    
	g_signal_connect_swapped (button[0], "clicked", G_CALLBACK (gtk_widget_destroy), dialog);
	g_signal_connect_swapped (button[1], "clicked", G_CALLBACK (prepare_text), &TextWidget);
}


static void
prepare_text (struct textWidget_t *TextWidget)
{
	gint ret;
	if (!TextWidget->action)
	{
		ret = check_pwd (TextWidget);
		if (ret == -1)
			return;
	}

	GtkTextIter start;
	GtkTextIter end;
	
	gtk_text_buffer_get_start_iter (TextWidget->buffer, &start);
	gtk_text_buffer_get_end_iter (TextWidget->buffer, &end);

	TextWidget->text = gtk_text_buffer_get_text (TextWidget->buffer, &start, &end, FALSE);
	
	if (!TextWidget->action)
	{
		crypt_text (TextWidget);

		gsize outBufLen = ( (TextWidget->totalLen/3 + 1) * 4 + 4) + ( ( (TextWidget->totalLen/3 + 1) * 4 + 4)/72 + 1);
		gsize outLen;
		gint state = 0, save = 0;

		gchar *encodedText = g_malloc0 (outBufLen);
		
		outLen = g_base64_encode_step (TextWidget->cryptText, TextWidget->totalLen, TRUE, encodedText, &state, &save);
		g_base64_encode_close (TRUE, encodedText + outLen, &state, &save);

		gtk_text_buffer_set_text (TextWidget->buffer, encodedText, -1);

		g_free (TextWidget->cryptText);
		g_free (encodedText);
	}
	else{
		TextWidget->cryptText = g_base64_decode (TextWidget->text, &(TextWidget->outLen));
				
		crypt_text (TextWidget);
		
		gtk_text_buffer_set_text (TextWidget->buffer, TextWidget->decodedText, -1);
		
		g_free (TextWidget->cryptText);
		g_free (TextWidget->decodedText);
	}
	
	g_free (TextWidget->text);
}


static void
crypt_text (struct textWidget_t *TextWidget)
{
	gint algo = -1, mode = -1, counterForGoto = 0;
	guchar *cryptoKey = NULL, *tmp = NULL;
	gsize blkLength, keyLength, textLen;
		
	gcry_cipher_hd_t hd;
	guchar iv[16];
	guchar salt[32];
	
	algo = gcry_cipher_map_name ("aes256");
	mode = GCRY_CIPHER_MODE_CTR;

	gsize keyLen = g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (TextWidget->pwd[0])), -1);

	blkLength = gcry_cipher_get_algo_blklen (algo);
	keyLength = gcry_cipher_get_algo_keylen (algo);	

	if (!TextWidget->action)
	{
		gcry_create_nonce (iv, 16);
		gcry_create_nonce (salt, 32);
	}
	else
	{
		memcpy (iv, TextWidget->cryptText, 16);
		memcpy (salt, TextWidget->cryptText+16, 32);	
	}
	
	gcry_cipher_open (&hd, algo, mode, 0);
	
	if ((cryptoKey = gcry_malloc_secure (32)) == NULL)
	{
		g_printerr ( _("encrypt_file: gcry_malloc_secure failed (crypto)\n"));
		return;
	}
	
	tryAgainDerive:
	if (gcry_kdf_derive (	gtk_entry_get_text (GTK_ENTRY (TextWidget->pwd[0])),
				keyLen,
				GCRY_KDF_PBKDF2,
				GCRY_MD_SHA256,
				salt,
				32, 150000, 32,
				cryptoKey) != 0)
	{
		if (counterForGoto == 3)
		{
			g_printerr ( _("encrypt_file: Key derivation error\n"));
			gcry_free (cryptoKey);
			return;
		}
		counterForGoto += 1;
		goto tryAgainDerive;
	}
	
	gtk_entry_set_text (GTK_ENTRY (TextWidget->pwd[0]), "");
	if (!TextWidget->action)
		gtk_entry_set_text(GTK_ENTRY(TextWidget->pwd[1]), "");
	
	gcry_cipher_setkey (hd, cryptoKey, keyLength);
	gcry_cipher_setiv (hd, iv, blkLength);
	
	if (!TextWidget->action)
	{
		TextWidget->totalLen = g_utf8_strlen (TextWidget->text, -1) + 16 + 32; //aggiungo iv e salt
		TextWidget->cryptText = g_malloc0 (TextWidget->totalLen);
		textLen = (TextWidget->totalLen) - 48;
		tmp = g_malloc (textLen);

		gcry_cipher_encrypt(hd, tmp, textLen, TextWidget->text, textLen);
	
		memcpy (TextWidget->cryptText, iv, 16);
		memcpy (TextWidget->cryptText + 16, salt, 32);
		memcpy (TextWidget->cryptText + 48, tmp, textLen);
		
		g_free (tmp);
	}
	else
	{
		gsize realLen = TextWidget->outLen - 48;
		TextWidget->decodedText = g_malloc0 (realLen);
	
		gcry_cipher_decrypt (hd, TextWidget->decodedText, realLen, TextWidget->cryptText + 48, realLen);
	}
	
	gcry_cipher_close (hd);
	gcry_free (cryptoKey);
}


gint
check_pwd (struct textWidget_t *TextWidget)
{
	if (g_strcmp0 (gtk_entry_get_text (GTK_ENTRY (TextWidget->pwd[0])), gtk_entry_get_text (GTK_ENTRY (TextWidget->pwd[1]))) != 0)
	{
		show_error ( _("Password are different, try again!"));
		return -1;
	}
	else
		return 0;
}


static void
show_error (const gchar *message)
{
	GtkWidget *dialog;
	dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", message);
	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_title (GTK_WINDOW (dialog), _("Error"));
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
}
