/* Sviluppatore: Paolo Stivanin
 * Copyright: 2013
 * Licenza: GNU GPL v3 <http://www.gnu.org/licenses/gpl-3.0.html>
 * Sito web: <https://github.com/polslinux/PolCrypt>
 */

#define GLIB_VERSION_2_32 (G_ENCODE_VERSION (2, 32))
#define GLIB_VERSION_MIN_REQUIRED (GLIB_VERSION_2_32)

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

/********************************************
 * TODO:
 * - Errori e uscite;
 * - Migliorare il codice;
 * - I commenti!!!!!!!!!!!!!!!!!!
 * - secure file deletion (vedere fsync, fclear)
 ********************************************/

int encrypt_file(const char *input_file_path, const char *output_file_path){
	int algo = -1, fd, number_of_block, block_done = 0;
	struct metadata s_mdata;
	struct termios oldt, newt;
	struct stat fileStat;
	memset(&s_mdata, 0, sizeof(struct metadata));
	unsigned char hex[15] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, plain_text[16];
	unsigned char *derived_key = NULL, *crypto_key = NULL, *mac_key = NULL, *encBuffer = NULL;
	char *input_key = NULL, *compare_key = NULL;
	float result_of_division_by_16, fsize_float;
	off_t fsize = 0;
	const char *name = "aes256";
	size_t blkLength, keyLength, txtLenght = 16, retval = 0, i, pwd_len;

	blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	algo = gcry_cipher_map_name(name);
	encBuffer = gcry_malloc(txtLenght);

	if(RAND_bytes(s_mdata.iv, 16) == 0){
		printf("Error on IV generation\n");
		return -1; // migliorare l'uscita
	}
	if(RAND_bytes(s_mdata.salt, 32) == 0){
		printf("Error on salt generation\n");
		return -1; // migliorare l'uscita
	}
	strncpy(s_mdata.header, "CREATED_BY_PolCrypt", sizeof(s_mdata.header));

 	if(((input_key = gcry_malloc_secure(256)) == NULL) || ((compare_key = gcry_malloc_secure(256)) == NULL)){
		perror("Memory allocation error\n");
		return -1;
	}
 	tcgetattr( STDIN_FILENO, &oldt);
  	newt = oldt;
	printf("Type password: ");
	newt.c_lflag &= ~(ECHO);
	tcsetattr( STDIN_FILENO, TCSANOW, &newt);
 	if(fgets(input_key, 254, stdin) == NULL){
 		perror("fgets input error\n");
 		tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
 		return -1;
 	}
 	tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
 	printf("\nRetype password: ");
 	newt.c_lflag &= ~(ECHO);
 	tcsetattr( STDIN_FILENO, TCSANOW, &newt);
 	if(fgets(compare_key, 254, stdin) == NULL){
 		perror("fgets input error\n");
 		tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
 		return -1;
 	}
 	tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
 	if(strcmp((const char *)input_key, (const char *)compare_key) != 0){
 		printf("\nPassword doesn't match\n");
 		free(input_key);
 		free(compare_key);
 		return -1;
 	}
 	printf("\n");
 	pwd_len = g_utf8_strlen(compare_key, 256)-1; // -1 perchè devo togliere \n di fgets. Devo usare glib perchè con strlen i caratteri utf8 come àèç valgono più di 1
 	gcry_free(input_key); // libero input_key...
    if(((input_key = gcry_malloc_secure(pwd_len)) == NULL)){ //...perchè voglio allocare la giusta quantità di spazio...
		perror("Memory allocation error\n");
		return -1;
	}
	g_utf8_strncpy(input_key, compare_key, pwd_len); //...per copiare la pwd SENZA \n\0 di fgets
	gcry_free(compare_key);

	fd = open(input_file_path, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		perror("open failed\n");
		return -1;
	}
  	if(fstat(fd, &fileStat) < 0){
  		perror("Fstat error");
  		gcry_free(input_key);
    	close(fd);
    	return -1;
  	}
  	fsize = fileStat.st_size; // file size in bytes
  	close(fd);

	fsize_float = (float)fsize; // file size in float
	result_of_division_by_16 = fsize_float / 16; // divisione per 16 bytes della grandezza in bytes
	number_of_block = (int)result_of_division_by_16; // numbero di blocchi in cui viene diviso
	if(result_of_division_by_16 > number_of_block) number_of_block += 1; // se il numero con virgola > del numero intero allora necessito di 1 blocco in più
	
	FILE *fp = fopen(input_file_path, "r");
	FILE *fpout = fopen(output_file_path, "w");
	if(fp == NULL || fpout == NULL){
		perror("File opening error\n");
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
		free(input_key);
		return -1;
	}
	memcpy(crypto_key, derived_key, 32); //i primi 32 byte (256bit) vanno alla chiave usata per cifrare il file
	memcpy(mac_key, derived_key + 32, 32); //gli ultimi 32 byte (256bit) vanno alla chiave usata per calcolare il MAC

	gcry_cipher_setkey(hd, crypto_key, keyLength);
	gcry_cipher_setiv(hd, s_mdata.iv, blkLength);

	fseek(fp, 0, SEEK_SET);
	
	fwrite(&s_mdata, sizeof(struct metadata), 1, fpout); // Ho scritto HEADER (2 blocchi) + IV (1 blocco) + SALT (2 blocchi)
	
	while(number_of_block > block_done){
		memset(plain_text, 0, sizeof(plain_text));
		retval = fread(plain_text, 1, 16, fp);
		if(!retval) break;
		if(retval < 16){
			//pkcs#7 se ho 5 blocchi liberi scrivo 0x05 nei blocchi rimanenti
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
		fwrite(encBuffer, 1, 16, fpout);
		block_done++;
	}
	
	unsigned char *hmac = calculate_hmac(output_file_path, mac_key, keyLength);
	if(hmac == (unsigned char *)-1){
		printf("Error during HMAC calculation\n");
		return -1;
	}
	fwrite(hmac, 1, 64, fpout);
	free(hmac);

	gcry_cipher_close(hd);
	gcry_free(input_key);
	gcry_free(derived_key);
	gcry_free(crypto_key);
	gcry_free(mac_key);
	gcry_free(encBuffer);
	fclose(fp);
	fclose(fpout);

	return 0;
}