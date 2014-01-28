#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include "polcrypt.h"

int encrypt_file(const char *input_file_path, const char *output_file_path){
	int algo = -1, fd, number_of_block, block_done = 0, retcode;
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

	gcry_create_nonce(s_mdata.iv, 16);
	gcry_create_nonce(s_mdata.salt, 32);

 	if(((input_key = gcry_malloc_secure(256)) == NULL) || ((compare_key = gcry_malloc_secure(256)) == NULL)){
		fprintf(stderr, "encrypt_file: memory allocation error\n");
		return -1;
	}
 	tcgetattr( STDIN_FILENO, &oldt);
  	newt = oldt;
	printf("Type password: ");
	newt.c_lflag &= ~(ECHO);
	tcsetattr( STDIN_FILENO, TCSANOW, &newt);
 	if(fgets(input_key, 254, stdin) == NULL){
 		fprintf(stderr, "encrypt_file: fgets error\n");
 		tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
 		return -1;
 	}
 	tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
 	printf("\nRetype password: ");
 	newt.c_lflag &= ~(ECHO);
 	tcsetattr( STDIN_FILENO, TCSANOW, &newt);
 	if(fgets(compare_key, 254, stdin) == NULL){
 		fprintf(stderr, "encrypt_file: fgets error\n");
 		tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
 		return -1;
 	}
 	tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
 	if(strcmp((const char *)input_key, (const char *)compare_key) != 0){
 		fprintf(stderr, "encrypt_file: password doesn't match\n");
 		free(input_key);
 		free(compare_key);
 		return -1;
 	}
 	printf("\n");
 	pwd_len = strlen(compare_key); //è gia 4 perchè con fgets ho \0\n quindi non serve fare +1
 	gcry_free(input_key);
    if(((input_key = gcry_malloc_secure(pwd_len)) == NULL)){
		fprintf(stderr, "encrypt_file: memory allocation error\n");
		return -1;
	}
	strncpy(input_key, compare_key, pwd_len);
	input_key[pwd_len-1] = '\0';
	gcry_free(compare_key);

	fd = open(input_file_path, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		fprintf(stderr, "encrypt_file: %s\n", strerror(errno));
		gcry_free(input_key);
		return -1;
	}
  	if(fstat(fd, &fileStat) < 0){
  		fprintf(stderr, "encrypt_file: %s\n", strerror(errno));
  		gcry_free(input_key);
    	close(fd);
    	return -1;
  	}
  	fsize = fileStat.st_size;
  	close(fd);

	fsize_float = (float)fsize;
	result_of_division_by_16 = fsize_float / 16;
	number_of_block = (int)result_of_division_by_16;
	if(result_of_division_by_16 > number_of_block) number_of_block += 1;
	
	FILE *fp = fopen(input_file_path, "r");
	FILE *fpout = fopen(output_file_path, "w");
	if(fp == NULL || fpout == NULL){
		fprintf(stderr, "encrypt_file: file opening error\n");
		gcry_free(input_key);
		return -1;
	}

	gcry_cipher_hd_t hd;
	gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CBC, 0);
	if(((derived_key = gcry_malloc_secure(64)) == NULL) || ((crypto_key = gcry_malloc_secure(32)) == NULL) || ((mac_key = gcry_malloc_secure(32)) == NULL)){
		fprintf(stderr, "encrypt_file: memory allocation error\n");
		gcry_free(input_key);
		return -1;
	}

	if(gcry_kdf_derive (input_key, pwd_len, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, s_mdata.salt, 32, 150000, 64, derived_key) != 0){
		fprintf(stderr, "encrypt_file: key derivation error\n");
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

	fseek(fp, 0, SEEK_SET);
	
	fwrite(&s_mdata, sizeof(struct metadata), 1, fpout);
	
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
		fwrite(encBuffer, 1, 16, fpout);
		block_done++;
	}
	fclose(fpout);
	fclose(fp);

	unsigned char *hmac = calculate_hmac(output_file_path, mac_key, keyLength, 0);
	if(hmac == (unsigned char *)1){
		fprintf(stderr, "encrypt_file: error during HMAC calculation\n");
		return -1;
	}
	fpout = fopen(output_file_path, "a");
	fwrite(hmac, 1, 64, fpout);
	free(hmac);
	
	retcode = delete_input_file(input_file_path, fsize);
	if(retcode == -1)
		fprintf(stderr, "encrypt_file: secure file deletion failed\n");
	if(retcode == -1)
		fprintf(stderr, "encrypt_file: file unlink failed\n");

	gcry_cipher_close(hd);
	gcry_free(input_key);
	gcry_free(derived_key);
	gcry_free(crypto_key);
	gcry_free(mac_key);
	gcry_free(encBuffer);
	fclose(fpout);

	return 0;
}
