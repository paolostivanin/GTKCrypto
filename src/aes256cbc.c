/* Sviluppatore: Paolo Stivanin
 * Versione: 1.0.0
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
#include "polcrypt.h"

#define GCRYPT_MIN_VER "1.5.0"


/* DATABASE FILE BINARIO (VEDERE LIBRO C) */

int main(int argc, char **argv){
	if(getuid() == 0){
		printf("You are root, please run this program as NORMAL USER!\n");
		return 0;
	}
	if(!gcry_check_version(GCRYPT_MIN_VER)){
		fputs("libgcrypt min version required: 1.5.0\n", stderr);
		exit(2);
	}
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	int retval, fd_input, fd_output;
	char *output_file;
	size_t output_len;
	const char *ext=".pcry";

	if(argc != 5){
		printf("Usage: %s <[-e] | [-d]> <path-to-input_file> -o <path_to_output_file>\n", argv[0]);
		return 0;
	}

	if(strcmp(argv[1], "-e") == 0 && strcmp(argv[2], "-d") != 0 && strcmp(argv[3], "-o") == 0){
		const char *path_to_input_file = argv[2];	
		output_len = strlen(argv[4])+1;
		output_file = malloc(output_len);
		strcpy(output_file, argv[4]);
		output_file = (char *)realloc(output_file, output_len+6);
		strcat(output_file, ext);
		const char *path_to_output_file = (const char *)output_file;

		fd_input = open(path_to_input_file, O_RDONLY | O_NOFOLLOW);
		fd_output = open(path_to_output_file, O_WRONLY | O_NOFOLLOW | O_CREAT, 0644);
		if(fd_input == -1 || fd_output == -1){
			perror("input or output file open failed\n");
			free(output_file);
			return -1;
		}
		close(fd_input);
		close(fd_output);
		retval = encrypt_file(path_to_input_file, path_to_output_file);
		if(retval == -1){
			printf("Error during file encryption\n");
			remove(path_to_output_file);
			free(output_file);
			return -1;
		}
		free(output_file);
	}

	if(strcmp(argv[1], "-d") == 0 && strcmp(argv[2], "-e") != 0 && strcmp(argv[3], "-o") == 0){
		const char *path_to_input_file = argv[2];
		const char *path_to_output_file = argv[4];

		fd_input = open(path_to_input_file, O_RDONLY | O_NOFOLLOW);
		fd_output = open(path_to_output_file, O_WRONLY | O_NOFOLLOW | O_CREAT, 0644);
		if(fd_input == -1 || fd_output == -1){
			perror("input or output file open failed\n");
			return -1;
		}
		close(fd_input);
		close(fd_output);
		retval = decrypt_file(path_to_input_file, path_to_output_file);
		if(retval == -1){
			printf("Error during file decryption\n");
			remove(path_to_output_file);
			return -1;
		}
	}
	return 0;
}