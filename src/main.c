#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include "polcrypt.h"

struct argvArgs args;

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

	int ch;
	size_t nameLen;
	args.check = 0;
	
	static struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'v'},
		{"encrypt", required_argument, NULL, 'e'},
		{"decrypt", required_argument, NULL, 'd'},
		{"output", required_argument, NULL, 'o'},
		{"hash", required_argument, NULL, 's'},
		{"algo", required_argument, NULL, 'a'},
		{NULL, 0, NULL, 0}
	};

	while ((ch = getopt_long(argc, argv, "v", long_options, NULL)) != -1){
			switch(ch){
			case 'v':
				printf("PolCrypt v%s developed by Paolo Stivanin <info@paolostivanin.com>\n", VERS);
				return 0;
			
			case 'h':
				printf("To encrypt|decrypt a file: %s [--encrypt] | [--decrypt] <path-to-input_file> --output <path_to_output_file>\n", argv[0]);
				printf("To calculate the hash of a file: %s --hash <path-to-input_file> --algo [md5|rmd160|sha1|sha256|sha512|whirlpool|all]\n", argv[0]);
				return 0;
			
			case '?':
				return -1;
			}
	}
	optind = 1;
	while ((ch = getopt_long(argc, argv, "e:d:s:a:o:", long_options, NULL)) != -1){
		switch (ch){
			case 'e':
				nameLen = strlen(optarg)+1;
				args.inputFilePath = malloc(nameLen);
				if(args.inputFilePath == NULL){
					printf("Error during memory allocation\n");
					return -1;
				}
				strcpy(args.inputFilePath, optarg);
				args.check = 1;
				break;

			case 'd':
				nameLen = strlen(optarg)+1;
				args.inputFilePath = malloc(nameLen);
				if(args.inputFilePath == NULL){
					printf("Error during memory allocation\n");
					return -1;
				}
				strcpy(args.inputFilePath, optarg);
				args.check = 2;
				break;
			
			case 's':
				nameLen = strlen(optarg)+1;
				args.inputFilePath = malloc(nameLen);
				if(args.inputFilePath == NULL){
					printf("Error during memory allocation\n");
					return -1;
				}
				strcpy(args.inputFilePath, optarg);
				args.check = 3;
				break;
			
			case 'a':
				if(args.check != 3){
					printf("You must use --hash to use the option --algo\n");
					return -1;
				}
				nameLen = strlen(optarg)+1;
				args.algo = malloc(nameLen);
				if(args.algo == NULL){
					printf("Error during memory allocation\n");
					return -1;
				}
				strcpy(args.algo, optarg);
				do_action();
				free(args.inputFilePath);
				free(args.algo);
				return 0;
				
			case 'o':
				if(args.check != 1 || args.check != 2){
					printf("You must use --encrypt || --decrypt to use the option --output\n");
					return -1;
				}
				nameLen = strlen(optarg)+1;
				args.outputFilePath = malloc(nameLen);
				if(args.outputFilePath == NULL){
					printf("Error during memory allocation\n");
					return -1;
				}
				strcpy(args.outputFilePath, optarg);
				do_action();
				free(args.inputFilePath);
				free(args.outputFilePath);
				return 0;
			
			case '?':
				return -1;
		}
	}
	return 0;
}

int do_action(){
	int retval, fd_input, fd_output;
	char *output_file;
	size_t output_len;
	const char *ext=".pcry";
	
	if(args.check == 1){
		output_len = strlen(args.outputFilePath)+1;
		output_file = malloc(output_len);
		strcpy(output_file, args.outputFilePath);
		output_file = (char *)realloc(output_file, output_len+6);
		strcat(output_file, ext);
		const char *path_to_output_file = (const char *)output_file;

		fd_input = open(args.inputFilePath, O_RDONLY | O_NOFOLLOW);
		fd_output = open(path_to_output_file, O_WRONLY | O_NOFOLLOW | O_CREAT, 0644);
		if(fd_input == -1 || fd_output == -1){
			perror("input or output file open failed\n");
			free(output_file);
			return -1;
		}
		close(fd_input);
		close(fd_output);
		retval = encrypt_file(args.inputFilePath, path_to_output_file);
		if(retval == -1){
			printf("Error during file encryption\n");
			remove(path_to_output_file);
			free(output_file);
			return -1;
		}
		free(output_file);
	}
	else if(args.check == 2){
		fd_input = open(args.inputFilePath, O_RDONLY | O_NOFOLLOW);
		fd_output = open(args.outputFilePath, O_WRONLY | O_NOFOLLOW | O_CREAT, 0644);
		if(fd_input == -1 || fd_output == -1){
			perror("input or output file open failed\n");
			return -1;
		}
		close(fd_input);
		close(fd_output);
		retval = decrypt_file(args.inputFilePath, args.outputFilePath);
		if(retval == -1){
			printf("Error during file decryption\n");
			remove(args.outputFilePath);
			return -1;
		}
	}
	else if(args.check == 3){
		if(strcmp(args.algo, "md5") == 0) compute_md5(args.inputFilePath);
		if(strcmp(args.algo, "rmd160") == 0) compute_rmd160(args.inputFilePath);
		if(strcmp(args.algo, "sha1") == 0) compute_sha1(args.inputFilePath);
		if(strcmp(args.algo, "sha256") == 0) compute_sha256(args.inputFilePath);
		if(strcmp(args.algo, "sha512") == 0) compute_sha512(args.inputFilePath);
		if(strcmp(args.algo, "whirlpool") == 0) compute_whirlpool(args.inputFilePath);
		if(strcmp(args.algo, "all") == 0){
			compute_md5(args.inputFilePath);
			compute_rmd160(args.inputFilePath);
			compute_sha1(args.inputFilePath);
			compute_sha256(args.inputFilePath);
			compute_sha512(args.inputFilePath);
			compute_whirlpool(args.inputFilePath);
		}
		else printf("--> Available hash algo are: md5, rmd160, sha1, sha256, sha512 and whirlpool\n");
	}
	return 0;
}
