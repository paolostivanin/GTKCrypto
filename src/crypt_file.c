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
	guchar text[16], MAC_of_file[64], *crypto_buffer = NULL;
	
	gint algo = -1, ret_val, i, cipher_mode = -1, number_of_block = -1, block_done = 0, number_of_pkcs7_bytes, counterForGoto = 0;	
	
	gchar *inputKey = NULL, *outFilename = NULL, *extBuf = NULL;
	gchar *filename = g_strdup (main_var->filename);
	
	gfloat divBy16;
	glong currentFileOffset, bytes_before_MAC;
	
	goffset file_size = 0, done_size = 0;
	gsize blkLength = 0, keyLength = 0, filename_length, pwd_len = 0;
	
	FILE *fp, *fpout;
	
	if (!g_utf8_validate (filename, -1, NULL))
	{
		send_notification ("ERROR", "The name of the file you chose isn't a valid UTF-8 string");
		return -2;
	}
	
	file_size = get_file_size (filename);
	
	crypto_buffer = gcry_malloc (16);
	if (crypto_buffer == NULL)
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
		
		filename_length = g_utf8_strlen (filename, -1);
		outFilename = g_malloc (filename_length+5); // ".enc\0" are 5 char
		g_utf8_strncpy (outFilename, filename, filename_length);
		memcpy (outFilename+filename_length, ".enc", 4);
		outFilename[filename_length+4] = '\0';
	}
	else
	{
		filename_length = g_utf8_strlen (filename, -1);
		extBuf = malloc(5);
		if (extBuf == NULL)
		{
			g_printerr ( _("crypt_file: error during memory allocation (extBuf)"));
			g_free (crypto_buffer);
			g_free (filename);
			return -1;
		}
		
		memcpy(extBuf, (filename)+filename_length-4, 4);
		extBuf[4] = '\0';
		if (g_strcmp0 (extBuf, ".enc") == 0)
		{
			outFilename = g_malloc (filename_length-3);
			strncpy (outFilename, filename, filename_length-4);
			outFilename[filename_length-4] = '\0';
			g_free (extBuf);
		}
		else
		{
			outFilename = g_malloc(filename_length+5);
			g_utf8_strncpy (outFilename, filename, filename_length);
			memcpy (outFilename+filename_length, ".dec", 4);
			outFilename[filename_length+4] = '\0';
			g_free (extBuf);
		}
	}
	
	const gchar *pwd = gtk_entry_get_text (GTK_ENTRY (main_var->pwd_entry[0]));
	if (!g_utf8_validate (pwd, -1, NULL))
	{
		send_notification ("ERROR", "The password you chose is not a valid UTF-8 string");
		free_res (filename, outFilename, crypto_buffer, NULL, NULL, NULL);
		return -2;
	}
	pwd_len = strlen(pwd);
	inputKey = gcry_malloc_secure (pwd_len+1);
	g_utf8_strncpy (inputKey, pwd, pwd_len);
	inputKey[pwd_len] = '\0';
		
	if (mode == ENCRYPT)
	{
		gcry_create_nonce(metadata.iv, 16);
		gcry_create_nonce(metadata.salt, 32);
		
		divBy16 = (gfloat) file_size / 16;
		number_of_block = (gint) divBy16;
		if (divBy16 > number_of_block)
			number_of_block += 1;
	}
	else
		file_size = file_size - 64 - sizeof (struct data);
	
	fp = g_fopen (filename, "r");
	if (fp == NULL)
	{
		g_printerr ("%s\n", strerror (errno));
		gcry_free (inputKey);
		free_res (filename, outFilename, crypto_buffer, NULL, NULL, NULL);
		return -3;
	}
	
	fpout = g_fopen (outFilename, "a");
	if (fpout == NULL)
	{
		g_printerr ("%s\n", strerror (errno));
		gcry_free (inputKey);
		free_res (filename, outFilename, crypto_buffer, NULL, NULL, NULL);
		fclose (fp);
		return -3;
	}
	
	if (mode == DECRYPT)
	{
		if (fseek (fp, 0, SEEK_SET) == -1)
		{
			g_printerr ("decrypt_file: %s\n", strerror(errno));
			free_res (filename, outFilename, crypto_buffer, NULL, NULL, NULL);
			close_file (fp, fpout);
			return -4;
		}
		
		if (fread (&metadata, sizeof (struct data), 1, fp) != 1)
		{
			g_printerr ( _("decrypt_file: cannot read file data\n"));
			free_res (filename, outFilename, crypto_buffer, NULL, NULL, NULL);
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
		free_res (filename, outFilename, crypto_buffer, NULL, NULL, NULL);
		close_file (fp, fpout);	
		return -1;
	}
	
	if ((crypto_key = gcry_malloc_secure (32)) == NULL)
	{
		g_printerr ( _("encrypt_file: gcry_malloc_secure failed (crypto)\n"));
		gcry_free (inputKey);
		free_res (filename, outFilename, crypto_buffer, derived_key, NULL, NULL);
		close_file (fp, fpout);		
		return -1;
	}
	
	if ((mac_key = gcry_malloc_secure (32)) == NULL)
	{
		g_printerr ( _("encrypt_file: gcry_malloc_secure failed (mac)\n"));
		gcry_free (inputKey);
		free_res (filename, outFilename, crypto_buffer, derived_key, crypto_key, NULL);
		close_file (fp, fpout);		
		return -1;
	}
	
	tryAgainDerive:
	if (gcry_kdf_derive (inputKey, pwd_len+1, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, metadata.salt, 32, 150000, 64, derived_key) != 0)
	{
		if (counterForGoto == 3)
		{
			g_printerr ( _("encrypt_file: Key derivation error\n"));
			gcry_free (inputKey);
			free_res (filename, outFilename, crypto_buffer, derived_key, crypto_key, mac_key);
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
		number_of_block = file_size / 16;
		bytes_before_MAC = file_size + sizeof(struct data);
				
		if ((currentFileOffset = ftell (fp)) == -1)
		{
			g_printerr ("decrypt_file: %s\n", strerror (errno));
			free_res (filename, outFilename, crypto_buffer, derived_key, crypto_key, mac_key);
			close_file (fp, fpout);
			return -4;
		}
		
		if (fseek (fp, bytes_before_MAC, SEEK_SET) == -1)
		{
			g_printerr ("decrypt_file: %s\n", strerror (errno));
			free_res (filename, outFilename, crypto_buffer, derived_key, crypto_key, mac_key);
			close_file (fp, fpout);
			return -4;
		}
		
		if (fread (MAC_of_file, 1, 64, fp) != 64)
		{
			g_printerr ("decrypt_file: %s\n", strerror (errno));
			free_res (filename, outFilename, crypto_buffer, derived_key, crypto_key, mac_key);
			close_file (fp, fpout);
			return -4;
		}

		guchar *hmac = calculate_hmac(filename, mac_key, keyLength, file_size, 1);
		if (hmac == (guchar *)1)
		{
			g_printerr ( _("Error during HMAC calculation\n"));
			gcry_free (inputKey);
			free_res (filename, outFilename, crypto_buffer, derived_key, crypto_key, mac_key);
			close_file (fp, fpout);
			return -4;
		}	

		if (memcmp (MAC_of_file, hmac, 64) != 0)
		{
			send_notification("PolCrypt", "HMAC doesn't match. This is caused by\n1) wrong password\nor\n2) corrupted file\n");
			free_res (filename, outFilename, crypto_buffer, derived_key, crypto_key, mac_key); //docazzooooooooooooooo
			free(hmac);
			close_file (fp, fpout);
			return -5;
		}
		free(hmac);
				
		if (fseek (fp, currentFileOffset, SEEK_SET) == -1)
		{
			g_printerr ("decrypt_file: %s\n", strerror (errno));
			free_res (filename, outFilename, crypto_buffer, derived_key, crypto_key, mac_key);
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
			while (number_of_block > block_done)
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
				gcry_cipher_encrypt (hd, crypto_buffer, 16, text, 16);
				fwrite(crypto_buffer, 1, 16, fpout);
				block_done++;
			}
		}
		else{
			while (file_size > done_size)
			{
				memset (text, 0, sizeof (text));
				ret_val = fread (text, 1, 16, fp);
				gcry_cipher_encrypt (hd, crypto_buffer, ret_val, text, ret_val);
				fwrite (crypto_buffer, 1, ret_val, fpout);
				done_size += ret_val;
			}
		}
		
		close_file (fp, fpout);
		
		guchar *hmac = calculate_hmac (outFilename, mac_key, keyLength, file_size, 0);
		if (hmac == (guchar *)1)
		{
			g_printerr ( _("Error during HMAC calculation"));
			free_res (filename, outFilename, crypto_buffer, derived_key, crypto_key, mac_key);
			return -4;
		}
		
		fpout = g_fopen (outFilename, "a");
		fwrite (hmac, 1, 64, fpout);
		free (hmac);
		
		ret_val = delete_input_file (filename, file_size);
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
			while (number_of_block > block_done)
			{
				memset (text, 0, sizeof (text));
				ret_val = fread (text, 1, 16, fp);
				gcry_cipher_decrypt (hd, crypto_buffer, ret_val, text, ret_val);
				if (block_done == (number_of_block-1))
				{
					number_of_pkcs7_bytes = check_pkcs7 (crypto_buffer, padding);
					fwrite (crypto_buffer, 1, number_of_pkcs7_bytes, fpout);	
					goto end;
				}
				fwrite (crypto_buffer, 1, ret_val, fpout);
				block_done++;
			}
		}
		else{
			while (file_size > done_size)
			{
				memset (text, 0, sizeof (text));
				if (file_size-done_size < 16)
				{
					ret_val = fread (text, 1, file_size-done_size, fp);
					gcry_cipher_decrypt (hd, crypto_buffer, ret_val, text, ret_val);
					fwrite (crypto_buffer, 1, ret_val, fpout);
					break;
				}
				else
				{
					ret_val = fread (text, 1, 16, fp);
					gcry_cipher_decrypt (hd, crypto_buffer, ret_val, text, ret_val);
					fwrite (crypto_buffer, 1, ret_val, fpout);
					done_size += ret_val;
				}
			}
		}
		end:
		gcry_free (inputKey);
		free_res (filename, outFilename, crypto_buffer, derived_key, crypto_key, mac_key);
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
	goffset file_size;

	file = g_file_new_for_path (filePath);
	info = g_file_query_info (file, attributes, flags, cancellable, &error);
	file_size = g_file_info_get_size (info);

	g_object_unref(file);
	
	return file_size;
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
       
        g_object_unref (G_OBJECT (n));
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
