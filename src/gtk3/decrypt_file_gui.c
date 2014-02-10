#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "polcrypt.h"

// INFO DIALOG TIPO "Decrypting input file"

int decrypt_file_gui(struct info *s_InfoDec){
	int algo = -1, fd, number_of_block, block_done = 0, number_of_pkcs7_byte;	
	struct metadata s_mdata;
	struct stat fileStat;
	memset(&s_mdata, 0, sizeof(struct metadata));
	unsigned char *derived_key = NULL, *crypto_key = NULL, *mac_key = NULL, *decBuffer = NULL;
	unsigned char hex[15] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, cipher_text[16], mac_of_file[64] ={0};
	char *inputKey = NULL;
	off_t fsize = 0;
	const char *name = "aes256";
	size_t blkLength, keyLength, txtLenght = 16, retval = 0, pwd_len;
	long current_file_offset, bytes_before_mac;
	FILE *fp, *fpout;

	blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	algo = gcry_cipher_map_name(name);
	decBuffer = gcry_malloc(txtLenght);
	
	char *outFilename = NULL, *extBuf = NULL;
	size_t lenFilename = strlen(s_InfoDec->filename);
	extBuf = malloc(5);
	if(extBuf == NULL){
		fprintf(stderr, "decrypt_file: error during memory allocation");
		return -1;
	}
	memcpy(extBuf, (s_InfoDec->filename)+lenFilename-4, 4);
	extBuf[5] = '\0';
	if(strcmp(extBuf, ".enc") == 0){
		outFilename = malloc(lenFilename-3);
		strncpy(outFilename, s_InfoDec->filename, lenFilename-4);
		outFilename[lenFilename-4] = '\0';
		free(extBuf);
	}
	else{
		outFilename = malloc(lenFilename+5);
		strncpy(outFilename, s_InfoDec->filename, lenFilename);
		memcpy(outFilename+lenFilename, ".dec", 4);
		outFilename[lenFilename+4] = '\0';
		free(extBuf);
	}


	const char *inputWidKey = gtk_entry_get_text(GTK_ENTRY(s_InfoDec->pwdEntry));
	pwd_len = strlen(inputWidKey);
	inputKey = gcry_malloc_secure(pwd_len+1);
	strncpy(inputKey, inputWidKey, pwd_len);
	inputKey[pwd_len] = '\0';

	fd = open(s_InfoDec->filename, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		fprintf(stderr, "decrypt_file: %s\n", strerror(errno));
		return -1;
	}
  	if(fstat(fd, &fileStat) < 0){
  		fprintf(stderr, "decrypt_file: %s\n", strerror(errno));
    	close(fd);
    	gcry_free(inputKey);
    	return -1;
  	}
  	fsize = fileStat.st_size;
  	close(fd);
	number_of_block = (fsize / 16)-8; //8=algo_type+salt+iv+hmac (1 blocco = 128bit)
	bytes_before_mac = (number_of_block+4)*16; //4=algo_type+salt+iv
	fp = fopen(s_InfoDec->filename, "r");
	if(fp == NULL){
		fprintf(stderr, "decrypt_file: %s\n", strerror(errno));
		gcry_free(inputKey);
		return -1;
	}
	if(fseek(fp, 0, SEEK_SET) == -1){
		fprintf(stderr, "decrypt_file: %s\n", strerror(errno));
		gcry_free(inputKey);
		return -1;
	}

	retval = fread(&s_mdata, sizeof(struct metadata), 1, fp);
	if(retval != 1){
		fprintf(stderr, "decrypt_file: cannot read file metadata\n");
		gcry_free(inputKey);
		return -1;
	}

	gcry_cipher_hd_t hd;
	gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CBC, 0);
	if(((derived_key = gcry_malloc_secure(64)) == NULL) || ((crypto_key = gcry_malloc_secure(32)) == NULL) || ((mac_key = gcry_malloc_secure(32)) == NULL)){
		fprintf(stderr, "decrypt_file: memory allocation error\n");
		gcry_free(inputKey);
		return -1;
	}

	if(gcry_kdf_derive (inputKey, pwd_len+1, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, s_mdata.salt, 32, 150000, 64, derived_key) != 0){
		fprintf(stderr, "decrypt_file: key derivation error\n");
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

	if((current_file_offset = ftell(fp)) == -1){
		fprintf(stderr, "decrypt_file: %s\n", strerror(errno));
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return -1;		
	}
	if(fseek(fp, bytes_before_mac, SEEK_SET) == -1){
		fprintf(stderr, "decrypt_file: %s\n", strerror(errno));
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return -1;		
	}
	if(fread(mac_of_file, 1, 64, fp) != 64){
		fprintf(stderr, "decrypt_file: fread mac error\n");;
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return -1;
	}
	unsigned char *hmac = calculate_hmac(s_InfoDec->filename, mac_key, keyLength, 1);
	if(hmac == (unsigned char *)1){
		fprintf(stderr, "decrypt_file: error during HMAC calculation\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return -1;
	}
	if(memcmp(mac_of_file, hmac, 64) != 0){
		fprintf(stderr, "--> CRITICAL ERROR: hmac doesn't match. This is caused by\n                    1) wrong password\n                    or\n                    2) corrupted file\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return -1;
	}
	free(hmac);
	if(fseek(fp, current_file_offset, SEEK_SET) == -1){
		fprintf(stderr, "decrypt_file: %s\n", strerror(errno));
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return -1;		
	}

	fpout = fopen(outFilename, "w");
	if(fpout == NULL){
		fprintf(stderr, "decrypt_file: %s\n", strerror(errno));
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return -1;
	}
	
	while(number_of_block > block_done){
		memset(cipher_text, 0, sizeof(cipher_text));
		retval = fread(cipher_text, 1, 16, fp);
		if(!retval) break;
		gcry_cipher_decrypt(hd, decBuffer, txtLenght, cipher_text, txtLenght);
		if(block_done == (number_of_block-1)){
			number_of_pkcs7_byte = check_pkcs7(decBuffer, hex);
			fwrite(decBuffer, 1, number_of_pkcs7_byte, fpout);	
			goto end;
		}
		fwrite(decBuffer, 1, 16, fpout);
		block_done++;
	}
	end:
	gcry_cipher_close(hd);
	gcry_free(inputKey);
	gcry_free(derived_key);
	gcry_free(crypto_key);
	gcry_free(mac_key);
	gcry_free(decBuffer);
	free(outFilename);
	fclose(fp);
	fclose(fpout);

	return 0;
}
