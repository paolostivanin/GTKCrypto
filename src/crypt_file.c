#include <gtk/gtk.h>
#include <glib.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include <libnotify/notify.h>
#include "polcrypt.h"

guchar *calculate_hmac(const gchar *, const guchar *, gsize, gint);
gint delete_input_file(const gchar *, gsize);
gint check_pkcs7(guchar *, guchar *);
static void send_notification(const gchar *, const gchar *);
goffset get_file_size (const gchar *);

gint
crypt_file(struct widget_t *Widget,
	   gint mode)
{
	struct metadata_t Metadata;
	gcry_cipher_hd_t hd;
	
	guchar padding[15] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	guchar *derivedKey = NULL, *cryptoKey = NULL, *macKey = NULL;
	guchar text[16], fileMAC[64], *cryptoBuffer = NULL;
	
	gint algo = -1, algoMode = -1, numberOfBlock = -1, blockDone = 0, numberOfPKCS7Bytes, retCode = 0, counterForGoto = 0;	
	
	gchar *inputKey = NULL, *outFilename = NULL, *extBuf = NULL;
	gchar *filename = g_strdup(Widget->filename); //remember to free it!!
	
	gfloat divBy16;
	glong currentFileOffset, bytesBeforeMAC;
	
	goffset fileSize = 0, doneSize = 0;
	gsize blkLength = 0, keyLength = 0, retVal = 0, i, lenFilename, pwdLen = 0, doneSize = 0;
	
	FILE *fp, *fpout;
	
	if (!g_utf8_validate (filename, -1, NULL))
	{
		send_notification ("ERROR", "The name of the file you chose isn't a valid UTF-8 string");
		return -2;
	}
	
	fileSize = get_file_size (filename);
	
	cryptoBuffer = gcry_malloc (16);
	if (cryptoBuffer == NULL)
	{
		g_printerr ( _("crypt_file: error during memory allocation (decBuffer)"));
		return -1;
	}
	
	if(mode == ENCRYPT)
	{
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (Widget->radioButton[0])))
		{
			algo = gcry_cipher_map_name ("aes256");
			Metadata.algoType = 0;
		}
		else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (Widget->radioButton[1])))
		{
			algo = gcry_cipher_map_name ("serpent256");
			Metadata.algoType = 1;
		}
		else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (Widget->radioButton[2])))
		{
			algo = gcry_cipher_map_name ("twofish");
			Metadata.algoType = 2;
		}
		else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (Widget->radioButton[3])))
		{
			algo = gcry_cipher_map_name ("camellia256");
			Metadata.algoType = 3;
		}
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (Widget->radioButton[4])))
		{
			algoMode = GCRY_CIPHER_MODE_CBC;
			Metadata.algoMode = 1;
		}
		else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (Widget->radioButton[5])))
		{
			algoMode = GCRY_CIPHER_MODE_CTR;
			Metadata.algoMode = 2;
		}
		
		lenFilename = g_utf8_strlen (filename, -1);
		outFilename = g_malloc (lenFilename+5); // ".enc\0" are 5 char
		g_utf8_strncpy (outFilename, filename, lenFilename);
		memcpy (outFilename+lenFilename, ".enc", 4);
		outFilename[lenFilename+4] = '\0';
	}
	else
	{
		lenFilename = g_utf8_strlen (filename, -1);
		extBuf = malloc(5);
		if (extBuf == NULL)
		{
			g_printerr ( _("crypt_file: error during memory allocation (extBuf)"));
			g_free (cryptoBuffer);
			g_free (filename);
			return -1;
		}
		
		memcpy(extBuf, (filename)+lenFilename-4, 4);
		extBuf[4] = '\0';
		if (g_strcmp0 (extBuf, ".enc") == 0)
		{
			outFilename = g_malloc (lenFilename-3);
			strncpy (outFilename, filename, lenFilename-4);
			outFilename[lenFilename-4] = '\0';
			g_free (extBuf);
		}
		else
		{
			outFilename = g_malloc(lenFilename+5);
			g_utf8_strncpy (outFilename, filename, lenFilename);
			memcpy (outFilename+lenFilename, ".dec", 4);
			outFilename[lenFilename+4] = '\0';
			g_free (extBuf);
		}
	}
	
	const gchar *pwd = gtk_entry_get_text (GTK_ENTRY (Widget->pwdEntry[0]));
	if (!g_utf8_validate (pwd, -1, NULL))
	{
		send_notification ("ERROR", "The password you chose is not a valid UTF-8 string");
		g_free (cryptoBuffer);
		g_free (filename);
		return -2;
	}
	pwdLen = strlen(pwd);
	inputKey = gcry_malloc_secure (pwdLen+1);
	g_utf8_strncpy (inputKey, pwd, pwdLen);
	inputKey[pwdLen] = '\0';
	
	if (mode == ENCRYPT)
	{
		gcry_create_nonce(Metadata.iv, 16);
		gcry_create_nonce(Metadata.salt, 32);
		
		divBy16 = (gfloat) fileSize / 16;
		numberOfBlock = (gint) divBy16;
		if (divBy16 > numberOfBlock)
			numberOfBlock += 1;
		
		fpout = g_fopen (outFilename, "w");
		if (fpout == NULL)
		{
			g_printerr ("%s\n", strerror (errno));
			gcry_free (inputKey);
			g_free (filename);
			g_free (cryptoBuffer);
			return -3;
		}
	}
	else
	{
		fileSize = fileSize-64-sizeof (struct metadata_t);
	}
	
	fp = g_fopen (filename, "r");
	if (fp == NULL)
	{
		g_printerr ("%s\n", strerror (errno));
		gcry_free (inputKey);
		g_free (filename);
		g_free (cryptoBuffer);
		if (mode == ENCRYPT)
			fclose (fpout);
		return -3;
	}
	
	if (mode == DECRYPT)
	{
		if (fseek (fp, 0, SEEK_SET) == -1)
		{
			g_printerr ("decrypt_file: %s\n", strerror(errno));
			//esci e free
		}
		
		if (fread (&Metadata, sizeof (struct metadata_t), 1, fp) != 1)
		{
			g_printerr ( _("decrypt_file: cannot read file metadata_t\n"));
			//esci e free
		}
		
		switch (Metada.algoType)
		{
			case 0:
				algo = gcry_cipher_map_name("aes256");
				break;
			case 1:
				algo = gcry_cipher_map_name("serpent256");
				break;
			case 2:
				algo = gcry_cipher_map_name("twofish");
				break;
			case 3:
				algo = gcry_cipher_map_name("camellia256");
				break;
			default:
				algo = gcry_cipher_map_name("aes256");
				break;
		}
		
		switch (Metadata.algoMode)
		{
			case 1:
				algoMode = GCRY_CIPHER_MODE_CBC;
				break;
			case 2:
				algoMode = GCRY_CIPHER_MODE_CTR;
				break;
			default:
				algoMode = GCRY_CIPHER_MODE_CTR;
				break;
		}
	}

	gcry_cipher_open (&hd, algo, algoMode, 0);
	
	blkLength = gcry_cipher_get_algo_blklen (algo);
	keyLength = gcry_cipher_get_algo_keylen (algo);
	
	if ((derivedKey = gcry_malloc_secure (64)) == NULL)
	{
		g_printerr ( _("encrypt_file: gcry_malloc_secure failed (derived)\n"));
		gcry_free (inputKey);
		g_free (filename);
		g_free (cryptoBuffer);
		fclose W(fp);
		if (mode == ENCRYPT)
			fclose (fpout);		
		return -4;
	}
	
	if ((cryptoKey = gcry_malloc_secure (32)) == NULL)
	{
		g_printerr ( _("encrypt_file: gcry_malloc_secure failed (crypto)\n"));
		gcry_free (inputKey);
		g_free (filename);
		g_free (cryptoBuffer);
		g_free (derivedKey);
		fclose (fp);
		if (mode == ENCRYPT)
			fclose (fpout);		
		return -4;
	}
	
	if ((macKey = gcry_malloc_secure (32)) == NULL)
	{
		g_printerr ( _("encrypt_file: gcry_malloc_secure failed (mac)\n"));
		gcry_free (inputKey);
		g_free (filename);
		g_free (cryptoBuffer);
		g_free (derivedKey);
		g_free (cryptoKey);
		fclose (fp);
		if (mode == ENCRYPT)
			fclose (fpout);		
		return -4;
	}
	
	tryAgainDerive:
	if (gcry_kdf_derive (inputKey, pwdLen+1, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, Metadata.salt, 32, 150000, 64, derived_key) != 0)
	{
		if (counterForGoto == 3)
		{
			g_printerr ( _("encrypt_file: Key derivation error\n"));
			gcry_free (inputKey);
			g_free (filename);
			g_free (cryptoBuffer);
			g_free (derivedKey);
			g_free (cryptoKey);
			fclose (fp);
			if (mode == ENCRYPT)
				fclose (fpout);	
		}
		counterForGoto += 1;
		goto tryAgainDerive;
	}
	
	memcpy (cryptoKey, derivedKey, 32);
	memcpy (macKey, derivedKey+32, 32);

	
	return 0;
}	


goffset
get_file_size (const gchar *filePath)
{
	GFileInfo *info;
	GFile *file;
	GError *error = NULL;
	const gchar *attributes = "standard::*";
	GFileQueryInfoFlags flags = G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS;
	GCancellable *cancellable = NULL;
	goffset fileSize;

	file = g_file_new_for_path (filePath);
	info = g_file_query_info (file, attributes, flags, cancellable, &error);
	fileSize = g_file_info_get_size (info);

	g_object_unref(file);
	
	return fileSize;
}


static void
send_notification (const gchar *title,
		   const gchar *message)
{
	NotifyNotification *n;
	notify_init ("org.gtk.polcrypt");
	n = notify_notification_new (title, message, NULL);
	notify_notification_set_timeout(n, 3000);
	if (!notify_notification_show (n, NULL))
		g_printerr ("Failed to send notification.\n");
        g_object_unrefv(G_OBJECTv(n));
}
