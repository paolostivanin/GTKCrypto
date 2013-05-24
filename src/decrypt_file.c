	/* Sviluppatore: Paolo Stivanin
 * Copyright: 2013
 * Licenza: GNU GPL v3 <http://www.gnu.org/licenses/gpl-3.0.html>
 * Sito web: <https://github.com/polslinux/PolCrypt>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include "polcrypt.h"

/********************************************
 * TODO:
 * - Errori e uscite
 * - Migliorare codice
 ********************************************/

int decrypt_file(const char *input_file_path, const char *output_file_path){
	int algo = -1, fd, number_of_block, block_done = 0, number_of_pkcs7_byte;	
	struct metadata s_mdata;
	struct termios oldt, newt;
	struct stat fileStat;
	memset(&s_mdata, 0, sizeof(struct metadata));
	unsigned char *derived_key = NULL, *crypto_key = NULL, *mac_key = NULL, *decBuffer = NULL;
	unsigned char hex[15] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}, cipher_text[16], mac_of_file[64] ={0};
	char *input_key = NULL, *tmp_key = NULL;
	off_t fsize = 0;
	const char *name = "aes256";
	size_t blkLength, keyLength, txtLenght = 16, retval = 0, pwd_len;
	long current_file_offset, bytes_before_mac;
	FILE *fp, *fpout;

	blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	algo = gcry_cipher_map_name(name);
	decBuffer = gcry_malloc(txtLenght);

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
 	pwd_len = strlen(tmp_key); 
 	if(((input_key = gcry_malloc_secure(pwd_len)) == NULL)){
		perror("Memory allocation error\n");
		return -1;
	}
	strncpy(input_key, tmp_key, strlen(tmp_key));
	input_key[pwd_len-1] = '\0';
	gcry_free(tmp_key);

	fd = open(input_file_path, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		perror("open failed\n");
		return -1;
	}
  	if(fstat(fd, &fileStat) < 0){
  		perror("Fstat error");
    	close(fd);
    	gcry_free(input_key);
    	return -1;
  	}
  	fsize = fileStat.st_size;
  	close(fd);
	number_of_block = (fsize / 16)-7;
	bytes_before_mac = (number_of_block+3)*16;
	fp = fopen(input_file_path, "r");
	if(fp == NULL){
		perror("Error on file opening\n");
		return -1;
	}
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

	if(gcry_kdf_derive (input_key, pwd_len, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, s_mdata.salt, 32, 150000, 64, derived_key) != 0){
		perror("Key derivation error\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(input_key);
		return -1;
	}
	memcpy(crypto_key, derived_key, 32);
	memcpy(mac_key, derived_key + 32, 32);
	gcry_cipher_setkey(hd, crypto_key, keyLength);
	gcry_cipher_setiv(hd, s_mdata.iv, blkLength);

	if((current_file_offset = ftell(fp)) == -1){
		perror("ftell\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(input_key);
		return -1;		
	}
	if(fseek(fp, bytes_before_mac, SEEK_SET) == -1){
		perror("fseek before mac\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(input_key);
		return -1;		
	}
	if(fread(mac_of_file, 1, 64, fp) != 64){
		perror("fread mac\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(input_key);
		return -1;
	}
	unsigned char *hmac = calculate_hmac(input_file_path, mac_key, keyLength, 1);
	if(hmac == (unsigned char *)-1){
		printf("Error during HMAC calculation\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(input_key);
		return -1;
	}
	if(memcmp(mac_of_file, hmac, 64) != 0){
		printf("--> CRITICAL ERROR: hmac doesn't match. This is caused by\n                    1) wrong password\n                    or\n                    2) corrupted file\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(input_key);
		return -1;
	}
	free(hmac);
	if(fseek(fp, current_file_offset, SEEK_SET) == -1){
		perror("ftell\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(input_key);
		return -1;		
	}

	fpout = fopen(output_file_path, "w");
	if(fpout == NULL){
		perror("Error on file opening\n");
		return -1;
	}

	while(number_of_block > block_done){
		memset(cipher_text, 0, sizeof(cipher_text));
		retval = fread(cipher_text, 1, 16, fp);
		if(!retval) break;
		gcry_cipher_decrypt(hd, decBuffer, txtLenght, cipher_text, txtLenght);
		if(block_done == (number_of_block-1)){
			if((number_of_pkcs7_byte = check_pkcs7(decBuffer, hex)) == -1){
				printf("Error on checking pkcs#7 padding\n");
				gcry_free(derived_key);
				gcry_free(crypto_key);
				gcry_free(mac_key);
				gcry_free(input_key);
				return -1;
			}
			fwrite(decBuffer, 1, number_of_pkcs7_byte, fpout);
			goto end;
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