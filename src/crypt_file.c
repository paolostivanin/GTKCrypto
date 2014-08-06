#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include <libnotify/notify.h>
#include "polcrypt.h"


static goffset get_file_size (const gchar *);
guchar *calculate_hmac (const gchar *, const guchar *, gsize, gsize, gint);
gint delete_input_file (const gchar *, gsize);
gint check_pkcs7 (guchar *, guchar *);
static void send_notification (const gchar *, const gchar *);
static void free_res (gchar *, gchar *, guchar *, guchar *, guchar *, guchar *);
static void close_file (FILE *, FILE *);


gint
crypt_file(	struct main_vars *main_var,
		gint mode)
{
	struct data metadata;
	gcry_cipher_hd_t hd;
	
	guchar padding[15] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	guchar *derived_key = NULL, *crypto_key = NULL, *mac_key = NULL;
	guchar text[16], fileMAC[64], *cryptoBuffer = NULL;
	
	gint algo = -1, ret_val, i, cipher_mode = -1, numberOfBlock = -1, blockDone = 0, numberOfPKCS7Bytes, counterForGoto = 0;	
	
	gchar *inputKey = NULL, *outFilename = NULL, *extBuf = NULL;
	gchar *filename = g_strdup(main_var->filename);
	
	gfloat divBy16;
	glong currentFileOffset, bytesBeforeMAC;
	
	goffset fileSize = 0, doneSize = 0;
	gsize blkLength = 0, keyLength = 0, lenFilename, pwdLen = 0;
	
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
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (main_var->radio_button[0])))
		{
			algo = gcry_cipher_map_name ("aes256");
			metadata.algo_type = 0;
		}
		else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (main_var->radio_button[1])))
		{
			algo = gcry_cipher_map_name ("serpent256");
			metadata.algo_type = 1;
		}
		else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (main_var->radio_button[2])))
		{
			algo = gcry_cipher_map_name ("twofish");
			metadata.algo_type = 2;
		}
		else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (main_var->radio_button[3])))
		{
			algo = gcry_cipher_map_name ("camellia256");
			metadata.algo_type = 3;
		}
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (main_var->radio_button[4])))
		{
			cipher_mode = GCRY_CIPHER_MODE_CBC;
			metadata.block_cipher_mode = 1;
		}
		else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (main_var->radio_button[5])))
		{
			cipher_mode = GCRY_CIPHER_MODE_CTR;
			metadata.block_cipher_mode = 2;
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
	
	const gchar *pwd = gtk_entry_get_text (GTK_ENTRY (main_var->pwd_entry[0]));
	if (!g_utf8_validate (pwd, -1, NULL))
	{
		send_notification ("ERROR", "The password you chose is not a valid UTF-8 string");
		free_res (filename, outFilename, cryptoBuffer, NULL, NULL, NULL);
		return -2;
	}
	pwdLen = strlen(pwd);
	inputKey = gcry_malloc_secure (pwdLen+1);
	g_utf8_strncpy (inputKey, pwd, pwdLen);
	inputKey[pwdLen] = '\0';
		
	if (mode == ENCRYPT)
	{
		gcry_create_nonce(metadata.iv, 16);
		gcry_create_nonce(metadata.salt, 32);
		
		divBy16 = (gfloat) fileSize / 16;
		numberOfBlock = (gint) divBy16;
		if (divBy16 > numberOfBlock)
			numberOfBlock += 1;
	}
	else
		fileSize = fileSize - 64 - sizeof (struct data);
	
	fp = g_fopen (filename, "r");
	if (fp == NULL)
	{
		g_printerr ("%s\n", strerror (errno));
		gcry_free (inputKey);
		free_res (filename, outFilename, cryptoBuffer, NULL, NULL, NULL);
		return -3;
	}
	
	fpout = g_fopen (outFilename, "a");
	if (fpout == NULL)
	{
		g_printerr ("%s\n", strerror (errno));
		gcry_free (inputKey);
		free_res (filename, outFilename, cryptoBuffer, NULL, NULL, NULL);
		fclose (fp);
		return -3;
	}
	
	if (mode == DECRYPT)
	{
		if (fseek (fp, 0, SEEK_SET) == -1)
		{
			g_printerr ("decrypt_file: %s\n", strerror(errno));
			free_res (filename, outFilename, cryptoBuffer, NULL, NULL, NULL);
			close_file (fp, fpout);
			return -4;
		}
		
		if (fread (&metadata, sizeof (struct data), 1, fp) != 1)
		{
			g_printerr ( _("decrypt_file: cannot read file data\n"));
			free_res (filename, outFilename, cryptoBuffer, NULL, NULL, NULL);
			close_file (fp, fpout);
			return -4;
		}
				
		switch (metadata.algo_type)
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

		switch (metadata.block_cipher_mode)
		{
			case 1:
				cipher_mode = GCRY_CIPHER_MODE_CBC;
				break;
			case 2:
				cipher_mode = GCRY_CIPHER_MODE_CTR;
				break;
			default:
				cipher_mode = GCRY_CIPHER_MODE_CTR;
				break;
		}
	}

	gcry_cipher_open (&hd, algo, cipher_mode, 0);
	
	blkLength = gcry_cipher_get_algo_blklen (algo);
	keyLength = gcry_cipher_get_algo_keylen (algo);
	
	if ((derived_key = gcry_malloc_secure (64)) == NULL)
	{
		g_printerr ( _("encrypt_file: gcry_malloc_secure failed (derived)\n"));
		gcry_free (inputKey);
		free_res (filename, outFilename, cryptoBuffer, NULL, NULL, NULL);
		close_file (fp, fpout);	
		return -1;
	}
	
	if ((crypto_key = gcry_malloc_secure (32)) == NULL)
	{
		g_printerr ( _("encrypt_file: gcry_malloc_secure failed (crypto)\n"));
		gcry_free (inputKey);
		free_res (filename, outFilename, cryptoBuffer, derived_key, NULL, NULL);
		close_file (fp, fpout);		
		return -1;
	}
	
	if ((mac_key = gcry_malloc_secure (32)) == NULL)
	{
		g_printerr ( _("encrypt_file: gcry_malloc_secure failed (mac)\n"));
		gcry_free (inputKey);
		free_res (filename, outFilename, cryptoBuffer, derived_key, crypto_key, NULL);
		close_file (fp, fpout);		
		return -1;
	}
	
	tryAgainDerive:
	if (gcry_kdf_derive (inputKey, pwdLen+1, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, metadata.salt, 32, 150000, 64, derived_key) != 0)
	{
		if (counterForGoto == 3)
		{
			g_printerr ( _("encrypt_file: Key derivation error\n"));
			gcry_free (inputKey);
			free_res (filename, outFilename, cryptoBuffer, derived_key, crypto_key, mac_key);
			close_file (fp, fpout);
		}
		counterForGoto += 1;
		goto tryAgainDerive;
	}
	
	memcpy (crypto_key, derived_key, 32);
	memcpy (mac_key, derived_key + 32, 32);
	
	gcry_cipher_setkey (hd, crypto_key, keyLength);
	if (cipher_mode == GCRY_CIPHER_MODE_CBC)
		gcry_cipher_setiv(hd, metadata.iv, blkLength);
	else
		gcry_cipher_setctr(hd, metadata.iv, blkLength);
	
	if (mode == DECRYPT)
	{
		numberOfBlock = fileSize / 16;
		bytesBeforeMAC = fileSize + sizeof(struct data);
				
		if ((currentFileOffset = ftell (fp)) == -1)
		{
			g_printerr ("decrypt_file: %s\n", strerror (errno));
			free_res (filename, outFilename, cryptoBuffer, derived_key, crypto_key, mac_key);
			close_file (fp, fpout);
			return -4;
		}
		
		if (fseek (fp, bytesBeforeMAC, SEEK_SET) == -1)
		{
			g_printerr ("decrypt_file: %s\n", strerror (errno));
			free_res (filename, outFilename, cryptoBuffer, derived_key, crypto_key, mac_key);
			close_file (fp, fpout);
			return -4;
		}
		
		if (fread (fileMAC, 1, 64, fp) != 64)
		{
			g_printerr ("decrypt_file: %s\n", strerror (errno));
			free_res (filename, outFilename, cryptoBuffer, derived_key, crypto_key, mac_key);
			close_file (fp, fpout);
			return -4;
		}

		guchar *hmac = calculate_hmac(filename, mac_key, keyLength, fileSize, 1);
		if (hmac == (guchar *)1)
		{
			g_printerr ( _("Error during HMAC calculation\n"));
			gcry_free (inputKey);
			free_res (filename, outFilename, cryptoBuffer, derived_key, crypto_key, mac_key);
			close_file (fp, fpout);
			return -4;
		}	

		if (memcmp (fileMAC, hmac, 64) != 0)
		{
			send_notification("PolCrypt", "HMAC doesn't match. This is caused by\n1) wrong password\nor\n2) corrupted file\n");
			free_res (filename, outFilename, cryptoBuffer, derived_key, crypto_key, mac_key); //docazzooooooooooooooo
			free(hmac);
			close_file (fp, fpout);
			return -5;
		}
		free(hmac);
				
		if (fseek (fp, currentFileOffset, SEEK_SET) == -1)
		{
			g_printerr ("decrypt_file: %s\n", strerror (errno));
			free_res (filename, outFilename, cryptoBuffer, derived_key, crypto_key, mac_key);
			close_file (fp, fpout);
			return -4;
		}		
	}
	
	if (mode == ENCRYPT)
	{
		fseek (fp, 0, SEEK_SET);
		fwrite (&metadata, sizeof(struct data), 1, fpout);
		if (cipher_mode == GCRY_CIPHER_MODE_CBC)
		{
			while (numberOfBlock > blockDone)
			{
				memset (text, 0, sizeof (text));
				ret_val = fread (text, 1, 16, fp);
				if (ret_val < 16)
				{
					for(i = ret_val; i < 16; i++)
					{
						if (ret_val == 1) text[i] = padding[14];
						else if (ret_val == 2) text[i] = padding[13];
						else if (ret_val == 3) text[i] = padding[12];
						else if (ret_val == 4) text[i] = padding[11];
						else if (ret_val == 5) text[i] = padding[10];
						else if (ret_val == 6) text[i] = padding[9];
						else if (ret_val == 7) text[i] = padding[8];
						else if (ret_val == 8) text[i] = padding[7];
						else if (ret_val == 9) text[i] = padding[6];
						else if (ret_val == 10) text[i] = padding[5];
						else if (ret_val == 11) text[i] = padding[4];
						else if (ret_val == 12) text[i] = padding[3];
						else if (ret_val == 13) text[i] = padding[2];
						else if (ret_val == 14) text[i] = padding[1];
						else if (ret_val == 15) text[i] = padding[0];
					}
				}
				gcry_cipher_encrypt (hd, cryptoBuffer, 16, text, 16);
				fwrite(cryptoBuffer, 1, 16, fpout);
				blockDone++;
			}
		}
		else{
			while (fileSize > doneSize)
			{
				memset (text, 0, sizeof (text));
				ret_val = fread (text, 1, 16, fp);
				gcry_cipher_encrypt (hd, cryptoBuffer, ret_val, text, ret_val);
				fwrite (cryptoBuffer, 1, ret_val, fpout);
				doneSize += ret_val;
			}
		}
		
		close_file (fp, fpout);
		
		guchar *hmac = calculate_hmac (outFilename, mac_key, keyLength, fileSize, 0);
		if (hmac == (guchar *)1)
		{
			g_printerr ( _("Error during HMAC calculation"));
			free_res (filename, outFilename, cryptoBuffer, derived_key, crypto_key, mac_key);
			return -4;
		}
		
		fpout = g_fopen (outFilename, "a");
		fwrite (hmac, 1, 64, fpout);
		free (hmac);
		
		ret_val = delete_input_file (filename, fileSize);
		if (ret_val == -1)
			g_printerr ( _("Secure file deletion failed, overwrite it manually"));
		if(ret_val == -2)
			g_printerr ( _("File unlink failed, remove it manually"));
			
		fclose(fpout);
		
		send_notification("PolCrypt", "Encryption successfully done");
	}
	else
	{
		if (cipher_mode == GCRY_CIPHER_MODE_CBC)
		{
			while (numberOfBlock > blockDone)
			{
				memset (text, 0, sizeof (text));
				ret_val = fread (text, 1, 16, fp);
				gcry_cipher_decrypt (hd, cryptoBuffer, ret_val, text, ret_val);
				if (blockDone == (numberOfBlock-1))
				{
					numberOfPKCS7Bytes = check_pkcs7 (cryptoBuffer, padding);
					fwrite (cryptoBuffer, 1, numberOfPKCS7Bytes, fpout);	
					goto end;
				}
				fwrite (cryptoBuffer, 1, ret_val, fpout);
				blockDone++;
			}
		}
		else{
			while (fileSize > doneSize)
			{
				memset (text, 0, sizeof (text));
				if (fileSize-doneSize < 16)
				{
					ret_val = fread (text, 1, fileSize-doneSize, fp);
					gcry_cipher_decrypt (hd, cryptoBuffer, ret_val, text, ret_val);
					fwrite (cryptoBuffer, 1, ret_val, fpout);
					break;
				}
				else
				{
					ret_val = fread (text, 1, 16, fp);
					gcry_cipher_decrypt (hd, cryptoBuffer, ret_val, text, ret_val);
					fwrite (cryptoBuffer, 1, ret_val, fpout);
					doneSize += ret_val;
				}
			}
		}
		end:
		gcry_free (inputKey);
		free_res (filename, outFilename, cryptoBuffer, derived_key, crypto_key, mac_key);
		close_file (fp, fpout);
		send_notification ("PolCrypt", "Decryption successfully done");
	}

	
	return 0;
}	


static goffset
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
send_notification (	const gchar *title,
			const gchar *message)
{
	NotifyNotification *n;
	notify_init ("org.gtk.polcrypt");
	n = notify_notification_new (title, message, NULL);
	notify_notification_set_timeout(n, 3000);
	if (!notify_notification_show (n, NULL))
		g_printerr ("Failed to send notification.\n");
        g_object_unref(G_OBJECT(n));
}


static void
free_res (	gchar *inFl,
		gchar *outFl,
		guchar *buf,
		guchar *dKey,
		guchar *crKey,
		guchar *mKey)
{
	if (inFl) g_free (inFl);
	if (outFl) g_free (outFl);
	if (buf) gcry_free (buf);
	if (dKey) gcry_free (dKey);
	if (crKey) gcry_free (crKey);
	if (mKey) gcry_free (mKey);
}


static void
close_file (	FILE *fpIn,
		FILE *fpOut)
{
	if (fpIn) fclose (fpIn);
	if (fpOut) fclose (fpOut);
}
