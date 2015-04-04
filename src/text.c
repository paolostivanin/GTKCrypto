#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <libnotify/notify.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "gtkcrypto.h"
#include "text.h"


static void prepare_text (GtkWidget *, gpointer);
static void crypt_text (struct text_vars *);


static void
close_dialog (	GtkWidget __attribute__((__unused__)) *bt,
				gpointer user_data)
{
	struct text_vars *text_var = user_data;
	gtk_widget_destroy (text_var->dialog);
	g_free (text_var);
}

void
text_dialog (	GtkWidget *clickedButton,
				gpointer user_data)
{	
	GtkWidget *content_area;
	GtkWidget *scrolled_win;
	GtkWidget *box;
	GtkWidget *button[2];
	
	struct text_vars *text_var = (struct text_vars *)g_malloc (sizeof (struct text_vars));
	text_var->parent = user_data;
		
	const gchar *btLabel = gtk_widget_get_name (clickedButton);
	if (g_strcmp0 (btLabel, "butEnTxt") == 0)
		text_var->action = 0;
	else
		text_var->action = 1;
		
	text_var->dialog = gtk_dialog_new ();
	gtk_window_set_transient_for (GTK_WINDOW (text_var->dialog), GTK_WINDOW (text_var->parent));
	gtk_window_set_title (GTK_WINDOW (text_var->dialog), _("Insert Text"));
	gtk_window_set_position (GTK_WINDOW (text_var->dialog), GTK_WIN_POS_CENTER);
	content_area = gtk_dialog_get_content_area (GTK_DIALOG (text_var->dialog));
	
	scrolled_win = gtk_scrolled_window_new (NULL, NULL);
	
	box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);

	gtk_widget_set_size_request (text_var->dialog, 800, 600);
	
	text_var->pwd[0] = gtk_entry_new ();
	text_var->pwd[1] = gtk_entry_new ();
	
	gtk_entry_set_visibility (GTK_ENTRY (text_var->pwd[0]), FALSE);
	gtk_entry_set_visibility (GTK_ENTRY (text_var->pwd[1]), FALSE);
	
	gtk_entry_set_placeholder_text (GTK_ENTRY (text_var->pwd[0]), _("Type Password"));
	gtk_entry_set_placeholder_text (GTK_ENTRY (text_var->pwd[1]), _("Retype Password"));
		
	text_var->text_view = gtk_text_view_new ();
	gtk_widget_set_name (GTK_WIDGET (text_var->text_view), "text_view");
	gtk_container_add (GTK_CONTAINER (scrolled_win), text_var->text_view);
	
	GtkCssProvider *css = gtk_css_provider_new ();
	gtk_css_provider_load_from_path (css, "./src/style.css", NULL); // !!!! >> change path to /usr/share/gtkcrypto << !!!!
	gtk_style_context_add_provider (gtk_widget_get_style_context (text_var->text_view), GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_USER);

	gtk_box_pack_start (GTK_BOX(box), text_var->pwd[0], TRUE, TRUE, 0);
	if (!text_var->action)
		gtk_box_pack_start (GTK_BOX (box), text_var->pwd[1], TRUE, TRUE, 0);
	
	g_object_set (text_var->text_view, "expand", TRUE, NULL);
	
	gtk_container_add (GTK_CONTAINER (content_area), scrolled_win);
	gtk_container_add (GTK_CONTAINER (content_area), box);
	
	button[0] = gtk_dialog_add_button (GTK_DIALOG (text_var->dialog), _("Cancel"), GTK_RESPONSE_CANCEL);
	button[1] = gtk_dialog_add_button (GTK_DIALOG (text_var->dialog), _("OK"), GTK_RESPONSE_OK);
	
	gtk_widget_set_name (GTK_WIDGET (button[0]), "clbt");
	gtk_widget_set_name (GTK_WIDGET (button[1]), "okbt");
		
	text_var->buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (text_var->text_view));

	gtk_text_buffer_set_text (text_var->buffer, _("Write here your text"), -1);
    
	gtk_widget_show_all (text_var->dialog);
    
	g_signal_connect (button[0], "clicked", G_CALLBACK (close_dialog), (gpointer)text_var);
	g_signal_connect (button[1], "clicked", G_CALLBACK (prepare_text), (gpointer)text_var);
}


static void
prepare_text (	GtkWidget __attribute__((__unused__)) *bt,
				gpointer user_data)
{
	struct text_vars *text_var = user_data;
	gboolean valid;
	gint ret;
	
	if (!text_var->action)
	{
		ret = check_pwd (text_var->pwd[0], text_var->pwd[1]);
		if (ret == -1)
		{
			error_dialog ( _("Passwords are different, try again."), text_var->parent);
			return;
		}
		else if (ret == -2)
		{
			error_dialog ( _("Password length must be >= 8"), text_var->parent);
			return;
		}
	}

	GtkTextIter start;
	GtkTextIter end;
	
	gtk_text_buffer_get_start_iter (text_var->buffer, &start);
	gtk_text_buffer_get_end_iter (text_var->buffer, &end);

	text_var->text = gtk_text_buffer_get_text (text_var->buffer, &start, &end, FALSE);
	
	if (!text_var->action)
	{
		crypt_text (text_var);

		gsize outBufLen = ( (text_var->total_length/3 + 1) * 4 + 4) + ( ( (text_var->total_length/3 + 1) * 4 + 4)/72 + 1);
		gsize out_length;
		gint state = 0, save = 0;

		gchar *encodedText = g_malloc0 (outBufLen);
		
		out_length = g_base64_encode_step (text_var->crypt_text, text_var->total_length, TRUE, encodedText, &state, &save);
		g_base64_encode_close (TRUE, encodedText + out_length, &state, &save);

		gtk_text_buffer_set_text (text_var->buffer, encodedText, -1);

		g_free (text_var->crypt_text);
		g_free (encodedText);
	}
	else{
		ret = check_b64 (text_var->text);
		if (ret == -1)
		{
			error_dialog ( _("This is not a base64 string, try again."), text_var->parent);
			return;
		}
		
		text_var->crypt_text = g_base64_decode (text_var->text, &(text_var->out_length));
				
		crypt_text (text_var);
		
		valid = g_utf8_validate (text_var->decoded_text, -1, NULL);
		if (!valid)
		{
			error_dialog ( _("The decoded text is not valid (maybe due to a wrong password)"), text_var->parent);
			return;
		}
		
		gtk_text_buffer_set_text (text_var->buffer, text_var->decoded_text, -1);
		
		g_free (text_var->crypt_text);
		g_free (text_var->decoded_text);
	}
	
	g_free (text_var->text);
}


static void
crypt_text (struct text_vars *text_var)
{
	gint algo = -1, mode = -1, counterForGoto = 0;
	guchar *cryptoKey = NULL, *tmp = NULL;
	gsize blkLength, keyLength, textLen;
		
	gcry_cipher_hd_t hd;
	guchar iv[16];
	guchar salt[32];
	
	algo = gcry_cipher_map_name ("aes256");
	mode = GCRY_CIPHER_MODE_CTR;

	gsize keyLen = g_utf8_strlen (gtk_entry_get_text (GTK_ENTRY (text_var->pwd[0])), -1);

	blkLength = gcry_cipher_get_algo_blklen (algo);
	keyLength = gcry_cipher_get_algo_keylen (algo);	

	if (!text_var->action)
	{
		gcry_create_nonce (iv, 16);
		gcry_create_nonce (salt, 32);
	}
	else
	{
		memcpy (iv, text_var->crypt_text, 16);
		memcpy (salt, text_var->crypt_text+16, 32);	
	}
	
	gcry_cipher_open (&hd, algo, mode, 0);
	
	if ((cryptoKey = gcry_malloc_secure (32)) == NULL)
	{
		g_printerr ( _("encrypt_file: gcry_malloc_secure failed (crypto)\n"));
		return;
	}
	
	tryAgainDerive:
	if (gcry_kdf_derive (	gtk_entry_get_text (GTK_ENTRY (text_var->pwd[0])),
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
	
	gtk_entry_set_text (GTK_ENTRY (text_var->pwd[0]), "");
	if (!text_var->action)
		gtk_entry_set_text(GTK_ENTRY(text_var->pwd[1]), "");
	
	gcry_cipher_setkey (hd, cryptoKey, keyLength);
	gcry_cipher_setiv (hd, iv, blkLength);
	
	if (!text_var->action)
	{
		text_var->total_length = strlen (text_var->text) + 16 + 32 + 1; // iv + salt + \0
		//PS: strlen counts bytes while g_utf8_strlen counts chars (strlen(àà)=4, g_utf8_strlen(àà) = 2)
		text_var->crypt_text = g_malloc0 (text_var->total_length);
		textLen = (text_var->total_length) - 48;
		tmp = g_malloc (textLen);

		gcry_cipher_encrypt(hd, tmp, textLen, text_var->text, textLen);
	
		memcpy (text_var->crypt_text, iv, 16);
		memcpy (text_var->crypt_text + 16, salt, 32);
		memcpy (text_var->crypt_text + 48, tmp, textLen);
		
		g_free (tmp);
	}
	else
	{
		text_var->real_len = text_var->out_length - 48;
		text_var->decoded_text = g_malloc0 (text_var->real_len + 1);
		gcry_cipher_decrypt (hd, text_var->decoded_text, text_var->real_len, text_var->crypt_text + 48, text_var->real_len);
		text_var->decoded_text[text_var->real_len] = '\0';
	}
	
	gcry_cipher_close (hd);
	gcry_free (cryptoKey);
}
