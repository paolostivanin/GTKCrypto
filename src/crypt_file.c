#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "gtkcrypto.h"
#include "crypt_file.h"


static void multiple_free (gchar *, gchar *, guchar *, guchar *, guchar *, guchar *);
static void multiple_fclose (FILE *, FILE *);
static void end_from_error (guint, struct main_vars *, const gchar *);


static void
add_text (	gpointer data,
		const gchar *text)
{
	gtk_progress_bar_set_show_text (GTK_PROGRESS_BAR(data), TRUE);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(data), text);
}


static gboolean
bar_full (gpointer data)
{
	/*PangoFontDescription *new_font = pango_font_description_new ();
	pango_font_description_set_weight (new_font, PANGO_WEIGHT_BOLD);
	gtk_widget_override_font (GTK_WIDGET (data), new_font);*/
    	
    	gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (data), 1);
	
	//pango_font_description_free (new_font);
	
    	return TRUE;
}


static gboolean
bar_pulse (gpointer data)
{
    	gtk_progress_bar_pulse (GTK_PROGRESS_BAR (data));
    	
    	return TRUE;
}


gpointer
crypt_file(gpointer user_data)
{
	struct data metadata;
	struct main_vars *main_var = user_data;
	
	guint id;
	
	if (main_var->encrypt)
		add_text (GTK_PROGRESS_BAR (main_var->pBar), _("Encrypting and deleting file..."));
	else
		add_text (GTK_PROGRESS_BAR (main_var->pBar), _("Decrypting file..."));
		
	id = g_timeout_add (100, bar_pulse, (gpointer)main_var->pBar);
	
	gcry_cipher_hd_t hd;
	
	guchar padding[15] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	guchar *derived_key = NULL, *crypto_key = NULL, *mac_key = NULL;
	guchar text[16], MAC_of_file[64], *crypto_buffer = NULL;
	
	gint algo = -1, ret_val, i, cipher_mode = -1, number_of_block = -1, block_done = 0, number_of_pkcs7_bytes, counter = 0;	
	
	gchar *inputKey = NULL, *output_fname = NULL, *extBuf = NULL;
	gchar *input_fname = g_strdup (main_var->filename);
	
	gfloat divBy16;
	glong current_file_offset, bytes_before_MAC;
	
	goffset file_size = 0, done_size = 0, output_file_size = 0;
	gsize blkLength = 0, keyLength = 0, filename_length, pwd_len = 0;
	
	FILE *fp, *fpout;
	
	file_size = get_file_size (input_fname);

	crypto_buffer = gcry_malloc (16);
	if (crypto_buffer == NULL)
	{
		end_from_error (id, main_var, _("error during memory allocation (crypto_buffer)"));
		g_thread_exit (NULL);
	}

	if(main_var->encrypt)
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
		
		filename_length = g_utf8_strlen (input_fname, -1);
		output_fname = g_malloc (filename_length+5); // ".enc\0" are 5 char
		g_utf8_strncpy (output_fname, input_fname, filename_length);
		memcpy (output_fname+filename_length, ".enc", 4);
		output_fname[filename_length+4] = '\0';
	}
	else
	{
		filename_length = g_utf8_strlen (input_fname, -1);
		extBuf = malloc (5);
		if (extBuf == NULL)
		{
			g_free (crypto_buffer);
			g_free (input_fname);
			end_from_error (id, main_var, _("error during memory allocation (extBuf)"));
			g_thread_exit (NULL);
		}
		
		memcpy(extBuf, (input_fname)+filename_length-4, 4);
		extBuf[4] = '\0';
		if (g_strcmp0 (extBuf, ".enc") == 0)
		{
			output_fname = g_malloc (filename_length-3);
			strncpy (output_fname, input_fname, filename_length-4);
			output_fname[filename_length-4] = '\0';
			g_free (extBuf);
		}
		else
		{
			output_fname = g_malloc(filename_length+5);
			g_utf8_strncpy (output_fname, input_fname, filename_length);
			memcpy (output_fname+filename_length, ".dec", 4);
			output_fname[filename_length+4] = '\0';
			g_free (extBuf);
		}
	}
	
	const gchar *pwd = gtk_entry_get_text (GTK_ENTRY (main_var->pwd_entry[0]));
	if (!g_utf8_validate (pwd, -1, NULL))
	{
		multiple_free (input_fname, output_fname, crypto_buffer, NULL, NULL, NULL);
		end_from_error (id, main_var, _("Error: password is not a valid UTF-8 string"));
		g_thread_exit (NULL);
	}
	pwd_len = strlen (pwd);
	inputKey = gcry_malloc_secure (pwd_len+1);
	g_utf8_strncpy (inputKey, pwd, pwd_len);
	inputKey[pwd_len] = '\0';
	
	if (main_var->encrypt)
	{
		gcry_create_nonce (metadata.iv, 16);
		gcry_create_nonce (metadata.salt, 32);
		
		divBy16 = (gfloat) file_size / 16;
		number_of_block = (gint) divBy16;
		
		if (divBy16 > number_of_block)
			number_of_block += 1;
	}
	else
		file_size = file_size - 64 - sizeof (struct data);
	
	fp = g_fopen (input_fname, "r");
	if (fp == NULL)
	{
		gcry_free (inputKey);
		multiple_free (input_fname, output_fname, crypto_buffer, NULL, NULL, NULL);
		end_from_error (id, main_var, _("g_fopen error (fp)"));
		g_thread_exit (NULL);
	}
	
	fpout = g_fopen (output_fname, "a");
	if (fpout == NULL)
	{
		g_printerr ("%s\n", strerror (errno));
		gcry_free (inputKey);
		multiple_free (input_fname, output_fname, crypto_buffer, NULL, NULL, NULL);
		fclose (fp);
		end_from_error (id, main_var, _("g_fopen error (fpout)"));
		g_thread_exit (NULL);
	}
	
	if (!main_var->encrypt)
	{
		if (fseek (fp, 0, SEEK_SET) == -1)
		{
			multiple_free (input_fname, output_fname, crypto_buffer, NULL, NULL, NULL);
			multiple_fclose (fp, fpout);
			end_from_error (id, main_var, _("fseek error"));
			g_thread_exit (NULL);
		}
		
		if (fread (&metadata, sizeof (struct data), 1, fp) != 1)
		{
			multiple_free (input_fname, output_fname, crypto_buffer, NULL, NULL, NULL);
			multiple_fclose (fp, fpout);
			end_from_error (id, main_var, _("fread error (metadata)"));
			g_thread_exit (NULL);
		}
		
		switch (metadata.algo_type)
		{
			case 0:
				algo = gcry_cipher_map_name ("aes256");
				break;
			case 1:
				algo = gcry_cipher_map_name ("serpent256");
				break;
			case 2:
				algo = gcry_cipher_map_name ("twofish");
				break;
			case 3:
				algo = gcry_cipher_map_name ("camellia256");
				break;
			default:
				algo = gcry_cipher_map_name ("aes256");
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
		gcry_free (inputKey);
		multiple_free (input_fname, output_fname, crypto_buffer, NULL, NULL, NULL);
		multiple_fclose (fp, fpout);
		end_from_error (id, main_var, _("error during memory allocation (derived_key)"));
		g_thread_exit (NULL);
	}
	
	if ((crypto_key = gcry_malloc_secure (32)) == NULL)
	{
		gcry_free (inputKey);
		multiple_free (input_fname, output_fname, crypto_buffer, derived_key, NULL, NULL);
		multiple_fclose (fp, fpout);		
		end_from_error (id, main_var, _("error during memory allocation (crypto_key)"));
		g_thread_exit (NULL);
	}
	
	if ((mac_key = gcry_malloc_secure (32)) == NULL)
	{
		gcry_free (inputKey);
		multiple_free (input_fname, output_fname, crypto_buffer, derived_key, crypto_key, NULL);
		multiple_fclose (fp, fpout);	
		end_from_error (id, main_var, _("error during memory allocation (mac_key)"));	
		g_thread_exit (NULL);
	}
	
	tryAgainDerive:
	if (gcry_kdf_derive (inputKey, pwd_len+1, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, metadata.salt, 32, 150000, 64, derived_key) != 0)
	{
		if (counter == 3)
		{
			gcry_free (inputKey);
			multiple_free (input_fname, output_fname, crypto_buffer, derived_key, crypto_key, mac_key);
			multiple_fclose (fp, fpout);
			end_from_error (id, main_var, _("key derivation error"));
			g_thread_exit (NULL);
		}
		counter += 1;
		goto tryAgainDerive;
	}
	
	memcpy (crypto_key, derived_key, 32);
	memcpy (mac_key, derived_key + 32, 32);
	
	gcry_cipher_setkey (hd, crypto_key, keyLength);
	if (cipher_mode == GCRY_CIPHER_MODE_CBC)
		gcry_cipher_setiv (hd, metadata.iv, blkLength);
	else
		gcry_cipher_setctr (hd, metadata.iv, blkLength);
	
	if (!main_var->encrypt)
	{
		number_of_block = file_size / 16;
		bytes_before_MAC = file_size + sizeof (struct data);
				
		if ((current_file_offset = ftell (fp)) == -1)
		{
			multiple_free (input_fname, output_fname, crypto_buffer, derived_key, crypto_key, mac_key);
			multiple_fclose (fp, fpout);
			end_from_error (id, main_var, _("ftell error"));
			g_thread_exit (NULL);
		}
		
		if (fseek (fp, bytes_before_MAC, SEEK_SET) == -1)
		{
			multiple_free (input_fname, output_fname, crypto_buffer, derived_key, crypto_key, mac_key);
			multiple_fclose (fp, fpout);
			end_from_error (id, main_var, _("fseek error"));
			g_thread_exit (NULL);
		}
		
		if (fread (MAC_of_file, 1, 64, fp) != 64)
		{
			multiple_free (input_fname, output_fname, crypto_buffer, derived_key, crypto_key, mac_key);
			multiple_fclose (fp, fpout);
			end_from_error (id, main_var, _("fread error (mac_of_file)"));
			g_thread_exit (NULL);
		}
		
		guchar *hmac = calculate_hmac (input_fname, mac_key, keyLength, file_size + sizeof (struct data));
		if (hmac == (guchar *)1)
		{
			gcry_free (inputKey);
			multiple_free (input_fname, output_fname, crypto_buffer, derived_key, crypto_key, mac_key);
			multiple_fclose (fp, fpout);
			end_from_error (id, main_var, _("error during hmac calculation"));
			g_thread_exit (NULL);
		}
		
		if (memcmp (MAC_of_file, hmac, 64) != 0)
		{
			main_var->hmac_error = TRUE;
			multiple_free (input_fname, output_fname, crypto_buffer, derived_key, crypto_key, mac_key);
			g_free (hmac);
			multiple_fclose (fp, fpout);
			end_from_error (id, main_var, _("ERROR: HMAC doesn't match (corrupted file or wrong password)"));
			g_thread_exit (NULL);
		}
		g_free (hmac);
				
		if (fseek (fp, current_file_offset, SEEK_SET) == -1)
		{
			multiple_free (input_fname, output_fname, crypto_buffer, derived_key, crypto_key, mac_key);
			multiple_fclose (fp, fpout);
			end_from_error (id, main_var, _("fseek error"));
			g_thread_exit (NULL);
		}		
	}
	
	if (main_var->encrypt)
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
		
		multiple_fclose (fp, fpout);
		
		output_file_size = get_file_size (output_fname);

		guchar *hmac = calculate_hmac (output_fname, mac_key, keyLength, output_file_size);
		if (hmac == (guchar *)1)
		{
			multiple_free (input_fname, output_fname, crypto_buffer, derived_key, crypto_key, mac_key);
			end_from_error (id, main_var, _("error during HMAC calculation (encrypt)"));
			pthread_exit (NULL);
		}
		
		fpout = g_fopen (output_fname, "a");
		fwrite (hmac, 1, 64, fpout);
		free (hmac);
		
		ret_val = delete_input_file (input_fname, file_size);
		if (ret_val == -1)
			end_from_error (id, main_var, _("Warning: failed to overwrite file, do it manually"));
		
		if(ret_val == -2)
			end_from_error (id, main_var, _("Warning: failed to remove file, do it manually"));
			
		fclose (fpout);
		
		g_source_remove (id);
		add_text (GTK_PROGRESS_BAR (main_var->pBar), _("Finished"));
		bar_full (GTK_PROGRESS_BAR (main_var->pBar));
		gtk_dialog_set_response_sensitive (GTK_DIALOG(main_var->bar_dialog), GTK_RESPONSE_REJECT, TRUE);
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
					break;
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

		gcry_free (inputKey);
		multiple_free (input_fname, output_fname, crypto_buffer, derived_key, crypto_key, mac_key);
		multiple_fclose (fp, fpout);

		g_source_remove (id);
		add_text (GTK_PROGRESS_BAR (main_var->pBar), _("Finished"));
		bar_full (GTK_PROGRESS_BAR (main_var->pBar));
		gtk_dialog_set_response_sensitive (GTK_DIALOG (main_var->bar_dialog), GTK_RESPONSE_REJECT, TRUE);
	}
	
	g_thread_exit (NULL);
}


static void
multiple_free (	gchar *inFl,
		gchar *outFl,
		guchar *buf,
		guchar *dKey,
		guchar *crKey,
		guchar *mKey)
{
	if (inFl)
		g_free (inFl);
	
	if (outFl)
		g_free (outFl);
	
	if (buf)
		gcry_free (buf);
	
	if (dKey)
		gcry_free (dKey);
	
	if (crKey)
		gcry_free (crKey);
	
	if (mKey)
		gcry_free (mKey);
}


static void
multiple_fclose (	FILE *fpIn,
			FILE *fpOut)
{
	if (fpIn)
		fclose (fpIn);
	
	if (fpOut)
		fclose (fpOut);
}


static void
end_from_error (guint id,
		struct main_vars *main_var,
		const gchar *message)
{
	g_source_remove (id);
	add_text (GTK_PROGRESS_BAR (main_var->pBar), message);
	bar_full (GTK_PROGRESS_BAR (main_var->pBar));
	gtk_dialog_set_response_sensitive (GTK_DIALOG (main_var->bar_dialog), GTK_RESPONSE_REJECT, TRUE);	
}
