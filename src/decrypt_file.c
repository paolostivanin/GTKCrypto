/* Sviluppatore: Paolo Stivanin
 * Copyright: 2013
 * Licenza: GNU GPL v3 <http://www.gnu.org/licenses/gpl-3.0.html>
 * Sito web: <https://github.com/polslinux/PolCrypt>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <openssl/rand.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <glib.h>
#include "polcrypt.h"

int decrypt_file(void){
	int algo = -1, fd, number_of_block, block_done = 0, number_of_pkcs7_byte;	
	struct metadata s_mdata;
	struct termios oldt, newt;
	memset(&s_mdata, 0, sizeof(struct metadata));
	unsigned char *derived_key = NULL, *crypto_key = NULL, *mac_key = NULL;
	unsigned char cipher_text[16];
	unsigned char *decBuffer = NULL;
	unsigned char hex[15] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	char *input_key = NULL, *tmp_key = NULL;
	off_t fsize = 0;
	struct stat fileStat;
	const char *name = "aes256";
	size_t blkLength, keyLength, txtLenght = 16, retval = 0, pwd_len;

 	if(((tmp_key = gcry_malloc_secure(256)) == NULL)){
		perror("Memory allocation error\n");
		return -1;
	}
 	tcgetattr( STDIN_FILENO, &oldt);
  	newt = oldt;
	printf("Type password: ");
	newt.c_lflag &= ~(ECHO);
	tcsetattr( STDIN_FILENO, TCSANOW, &newt);
 	if(fgets(tmp_key, 254, stdin) == NULL){
 		perror("fgets input error\n");
 		tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
 		return -1;
 	}
 	tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
 	printf("\n");
 	pwd_len = g_utf8_strlen(tmp_key, 256)-1;
 	if(((input_key = gcry_malloc_secure(pwd_len)) == NULL)){
		perror("Memory allocation error\n");
		return -1;
	}
	g_utf8_strncpy(input_key, tmp_key, pwd_len); //...per copiare la pwd SENZA \n\0 di fgets
	gcry_free(tmp_key);

	blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);

	fd = open("out", O_RDONLY);
  	if(fstat(fd, &fileStat) < 0){
  		perror("Fstat error");
    	close(fd);
    	gcry_free(input_key);
    	return -1;
  	}
  	fsize = fileStat.st_size; // file size in bytes
  	close(fd);
	number_of_block = (fsize / 16)-5; /* a differenza della cifratura qua avrò sempre un numero divisibile per 16 e devo fare - 5 perchè
									   * perchè 2 blocchi vanno all'header, 1 blocco va all'IV e 2 al SALT*/
	
	FILE *fp = fopen("out", "r");
	FILE *fpout = fopen("origdec", "w");
	if(fp == NULL || fpout == NULL){
		perror("Error on file opening\n");
		exit(1); // migliorare l'uscita
	}
	algo = gcry_cipher_map_name(name);
	decBuffer = gcry_malloc(txtLenght);

	fseek(fp, 0, SEEK_SET);

	retval = fread(&s_mdata, sizeof(struct metadata), 1, fp);
	if(retval != 1){
		printf("Cannot read file metadata\n");
		gcry_free(input_key);
		return -1;
	}

	gcry_cipher_hd_t hd;
	gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CBC, 0);
	if(((derived_key = gcry_malloc_secure(64)) == NULL) || ((crypto_key = gcry_malloc_secure(32)) == NULL) || ((mac_key = gcry_malloc_secure(32)) == NULL)){
		perror("Memory allocation error\n");
		gcry_free(input_key);
		return -1;
	}
	//chiave_input,grandezza chiave_input, algoritmo_derivazione, algoritmo_hash, salt, lunghezza salt, iterazioni, BYTES (64B=512bit), output_buffer
	if(gcry_kdf_derive (input_key, pwd_len, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, s_mdata.salt, 32, 150000, 64, derived_key) != 0){
		perror("Key derivation error\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(input_key);
		return -1;
	}
	memcpy(crypto_key, derived_key, 32); //i primi 32 byte (256bit) vanno alla chiave usata per cifrare il file
	memcpy(mac_key, derived_key + 32, 32); //gli ultimi 32 byte (256bit) vanno alla chiave usata per calcolare il MAC
	gcry_cipher_setkey(hd, crypto_key, keyLength);
	gcry_cipher_setiv(hd, s_mdata.iv, blkLength);

	while(number_of_block > block_done){
		memset(cipher_text, 0, sizeof(cipher_text));
		retval = fread(cipher_text, 1, 16, fp);
		if(!retval) break;
		gcry_cipher_decrypt(hd, decBuffer, txtLenght, cipher_text, txtLenght);
		if(block_done == (number_of_block-1)){ // se i blocchi fatti (che iniziano da 0) sono equivalenti ai blocchi totali-1 (ovvero all'ultimo blocco)..
			// ..allora cerco su decBuffer il padding...
			if((number_of_pkcs7_byte = check_pkcs7(decBuffer, hex)) == -1){
				printf("Error on checking pkcs#7 padding\n");
				// qua devo liberare le risorse quando esco
				return -1;
			}
			fwrite(decBuffer, 1, number_of_pkcs7_byte, fpout); //..e quando lo trovo scrivo solo i byte necessari..
			goto end; //..e vado alla fine
		}
		fwrite(decBuffer, 1, 16, fpout);
		block_done++;
	}
	end:
	gcry_cipher_close(hd);
	gcry_free(input_key);
	gcry_free(derived_key);
	gcry_free(crypto_key);
	gcry_free(mac_key);
	gcry_free(decBuffer);
	fclose(fp);
	fclose(fpout);

	return 0;
}