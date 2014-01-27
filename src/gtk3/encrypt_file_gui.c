#include <gtk/gtk.h>
#include <glib.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "polcrypt.h"


int encrypt_file_gui(struct info *s_InfoEnc){
	int algo = -1, fd, number_of_block, block_done = 0, retcode;
	struct metadata s_mdata;
	struct stat fileStat;
	memset(&s_mdata, 0, sizeof(struct metadata));
	unsigned char hex[15] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, plain_text[16];
	unsigned char *derived_key = NULL, *crypto_key = NULL, *mac_key = NULL, *encBuffer = NULL;
	char *inputKey = NULL;
	float result_of_division_by_16, fsize_float;
	off_t fsize = 0;
	const char *name = "aes256";
	size_t blkLength, keyLength, txtLenght = 16, retval = 0, i;
	
	const char *inputWidKey = gtk_entry_get_text(GTK_ENTRY(s_InfoEnc->pwdEntry));
	size_t len = strlen(inputWidKey);
	inputKey = gcry_malloc_secure(len+1);
	strncpy(inputKey, inputWidKey, len);
	inputKey[len] = '\0';

	char *outFilename;
	size_t lenFilename = strlen(s_InfoEnc->filename);
	outFilename = malloc(lenFilename+5); // ".enc\0" sono 5 chars
	strncpy(outFilename, s_InfoEnc->filename, lenFilename);
	memcpy(outFilename+lenFilename, ".enc", 4);
	outFilename[lenFilename+4] = '\0';

	blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	algo = gcry_cipher_map_name(name);
	encBuffer = gcry_malloc(txtLenght);

	gcry_create_nonce(s_mdata.iv, 16);
	gcry_create_nonce(s_mdata.salt, 32);

	fd = open(s_InfoEnc->filename, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		fprintf(stderr, "encrypt_file: %s\n", strerror(errno));
		gcry_free(inputKey);
		return -1;
	}
  	if(fstat(fd, &fileStat) < 0){
  		fprintf(stderr, "encrypt_file: %s\n", strerror(errno));
  		gcry_free(inputKey);
    	close(fd);
    	return -1;
  	}
  	fsize = fileStat.st_size;
  	close(fd);

	fsize_float = (float)fsize;
	result_of_division_by_16 = fsize_float / 16;
	number_of_block = (int)result_of_division_by_16;
	if(result_of_division_by_16 > number_of_block) number_of_block += 1;
	
	FILE *fp = fopen(s_InfoEnc->filename, "r");
	FILE *fpout = fopen(outFilename, "w");
	if(fp == NULL || fpout == NULL){
		fprintf(stderr, "encrypt_file: file opening error\n");
		gcry_free(inputKey);
		return -1;
	}

	gcry_cipher_hd_t hd;
	gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CBC, 0);
	if(((derived_key = gcry_malloc_secure(64)) == NULL) || ((crypto_key = gcry_malloc_secure(32)) == NULL) || ((mac_key = gcry_malloc_secure(32)) == NULL)){
		fprintf(stderr, "encrypt_file: memory allocation error\n");
		gcry_free(inputKey);
		return -1;
	}

	if(gcry_kdf_derive (inputKey, len+1, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, s_mdata.salt, 32, 150000, 64, derived_key) != 0){
		fprintf(stderr, "encrypt_file: key derivation error\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return -1;
	}
	memcpy(crypto_key, derived_key, 32);
	memcpy(mac_key, derived_key + 32, 32);

	gcry_cipher_setkey(hd, crypto_key, keyLength);
	gcry_cipher_setiv(hd, s_mdata.iv, blkLength);

	fseek(fp, 0, SEEK_SET);
	
	fwrite(&s_mdata, sizeof(struct metadata), 1, fpout);
	
	/* FROM HERE... */
	int nLastPct = -1, pct;
	gfloat pvalue;
	GtkWidget *content_area, *progressbar;
	GtkWidget *dd = gtk_dialog_new();
	gtk_window_set_title(GTK_WINDOW(dd), "Progress...");
	progressbar = gtk_progress_bar_new();
	content_area = gtk_dialog_get_content_area (GTK_DIALOG (dd));
	gtk_widget_set_size_request(dd, 200, 50);
   	gtk_container_add (GTK_CONTAINER (content_area), progressbar);
   	gtk_widget_show_all (dd);
	/* ...TO HERE IS FOR THE PROGRESS BAR */
	
	gtk_widget_hide(GTK_WIDGET(s_InfoEnc->dialog));
	while(number_of_block > block_done){
		memset(plain_text, 0, sizeof(plain_text));
		retval = fread(plain_text, 1, 16, fp);
		if(!retval) break;
		if(retval < 16){
			for(i=retval; i<16; i++){
				if(retval == 1) plain_text[i] = hex[14];
				if(retval == 2) plain_text[i] = hex[13];
				if(retval == 3) plain_text[i] = hex[12];
				if(retval == 4) plain_text[i] = hex[11];
				if(retval == 5) plain_text[i] = hex[10];
				if(retval == 6) plain_text[i] = hex[9];
				if(retval == 7) plain_text[i] = hex[8];
				if(retval == 8) plain_text[i] = hex[7];
				if(retval == 9) plain_text[i] = hex[6];
				if(retval == 10) plain_text[i] = hex[5];
				if(retval == 11) plain_text[i] = hex[4];
				if(retval == 12) plain_text[i] = hex[3];
				if(retval == 13) plain_text[i] = hex[2];
				if(retval == 14) plain_text[i] = hex[1];
				if(retval == 15) plain_text[i] = hex[0];
			}
		}
		gcry_cipher_encrypt(hd, encBuffer, txtLenght, plain_text, txtLenght);
		
		/* FROM HERE... */
		pvalue = (gfloat) block_done / (gfloat) number_of_block;
		pct = pvalue * 100;
		if (nLastPct != pct){
			gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (progressbar), pvalue);
			while(gtk_events_pending ()){
				gtk_main_iteration ();
			}
            nLastPct = pct;
        }
        /* ...TO HERE IS FOR THE PROGRESS BAR */
        
		fwrite(encBuffer, 1, 16, fpout);
		block_done++;
	}
	fclose(fpout);
	fclose(fp);
	
	//AND ALSO THIS IS FOR THE PROGRESS BAR
	gtk_widget_destroy (dd);	

	unsigned char *hmac = calculate_hmac(outFilename, mac_key, keyLength, 0);
	if(hmac == (unsigned char *)1){
		fprintf(stderr, "encrypt_file: error during HMAC calculation\n");
		gcry_free(inputKey);
		return -1;
	}
	fpout = fopen(outFilename, "a");
	fwrite(hmac, 1, 64, fpout);
	free(hmac);
	
	retcode = delete_input_file(s_InfoEnc, fsize);
	if(retcode == -1)
		fprintf(stderr, "encrypt_file: secure file deletion failed\n");
	if(retcode == -1)
		fprintf(stderr, "encrypt_file: file unlink failed\n");

	gcry_cipher_close(hd);
	gcry_free(derived_key);
	gcry_free(crypto_key);
	gcry_free(mac_key);
	gcry_free(encBuffer);
	gcry_free(inputKey);
	free(outFilename);
	fclose(fpout);

	return 0;
}
