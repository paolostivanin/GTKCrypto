/* Sviluppatore: Paolo Stivanin
 * Versione: 1.0-alpha
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

#define GCRYPT_MIN_VER "1.5.0"

int main(int argc, char **argv){
	if(!gcry_check_version(GCRYPT_MIN_VER)){
		fputs("libgcrypt min version required: 1.5.0\n", stderr);
		exit(2);
	}
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

	int retval;

	if(argc != 2){
		printf("Usage: %s [-e] | [-d]\n", argv[0]);
		return 0;
	}

	if(strcmp(argv[1], "-e") == 0){
		retval = encrypt_file();
		if(retval == -1){
			printf("Error during file encryption\n");
			return -1;
		}
	}

	if(strcmp(argv[1], "-d") == 0){
		retval = decrypt_file();
		if(retval == -1){
			printf("Error during file decryption\n");
			return -1;
		}
	}

	return 0;
}