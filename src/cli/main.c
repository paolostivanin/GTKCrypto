#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "polcrypt.h"

int encrypt_file(const char *, const char *);
int decrypt_file(const char *, const char *);
int compute_sha1(const char *);
int compute_sha256(const char *);
int compute_sha512(const char *);
int compute_md5(const char *);
int compute_whirlpool(const char *);
int compute_all(const char *);
int do_action();

struct argvArgs_t Args;

int main(int argc, char **argv){
	if(argc == 1){
		printf(_("To encrypt|decrypt a file: %s [--encrypt] | [--decrypt] <path-to-input_file> --output <path_to_output_file>\n"), argv[0]);
		printf(_("To calculate one or more file hash: %s --hash <path-to-input_file> --algo [md5|sha1|sha256|sha512|whirlpool|all]\n"), argv[0]);
	}
	
	if(getuid() == 0){
		printf(_("You are root, please run this program as NORMAL USER!\n"));
		return 0;
	}
	if(!gcry_check_version(GCRYPT_MIN_VER)){
		printf(_("libgcrypt min version required: 1.5.0\n"));
		return -1;
	}
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALE_DIR);
	textdomain(PACKAGE);

	int ch;
	size_t nameLen;
	Args.check = 0;
	
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
				printf(_("PolCrypt v%s developed by Paolo Stivanin <info@paolostivanin.com>\n"), VERSION);
				return 0;
			
			case 'h':
				printf(_("To encrypt|decrypt a file: %s [--encrypt] | [--decrypt] <path-to-input_file> --output <path_to_output_file>\n"), argv[0]);
				printf(_("To calculate one or more file hash: %s --hash <path-to-input_file> --algo [md5|sha1|sha256|sha512|whirlpool|all]\n"), argv[0]);
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
				Args.inputFilePath = malloc(nameLen);
				if(Args.inputFilePath == NULL){
					fprintf(stderr, _("main (case e): error during memory allocation\n"));
					return -1;
				}
				strcpy(Args.inputFilePath, optarg);
				Args.check = 1;
				break;

			case 'd':
				nameLen = strlen(optarg)+1;
				Args.inputFilePath = malloc(nameLen);
				if(Args.inputFilePath == NULL){
					fprintf(stderr, _("main (case d): error during memory allocation\n"));;
					return -1;
				}
				strcpy(Args.inputFilePath, optarg);
				Args.check = 2;
				break;
			
			case 's':
				nameLen = strlen(optarg)+1;
				Args.inputFilePath = malloc(nameLen);
				if(Args.inputFilePath == NULL){
					fprintf(stderr, _("main (case s): error during memory allocation\n"));
					return -1;
				}
				strcpy(Args.inputFilePath, optarg);
				Args.check = 3;
				if(optind == argc){
					fprintf(stderr, _("You must select an hash algo. Use --help for more information\n"));
					return -1;
				}
				break;
			
			case 'a':
				if(Args.check != 3){
					printf(_("You must use the option --hash to use the option --algo\n"));
					return -1;
				}
				nameLen = strlen(optarg)+1;
				Args.algo = malloc(nameLen);
				if(Args.algo == NULL){
					fprintf(stderr, _("main (case a): error during memory allocation\n"));
					return -1;
				}
				strcpy(Args.algo, optarg);
				do_action();
				free(Args.inputFilePath);
				free(Args.algo);
				return 0;
				
			case 'o':
				if(Args.check != 1 && Args.check != 2){
					printf(_("You must use the option --encrypt || --decrypt to use the option --output\n"));
					return -1;
				}
				nameLen = strlen(optarg)+1;
				Args.outputFilePath = malloc(nameLen);
				if(Args.outputFilePath == NULL){
					fprintf(stderr, _("main (case o): error during memory allocation\n"));
					return -1;
				}
				strcpy(Args.outputFilePath, optarg);
				do_action();
				free(Args.inputFilePath);
				free(Args.outputFilePath);
				return 0;
			
			case '?':
				fprintf(stderr, _("Unknown option\n"));
				return -1;
		}
	}
	return 0;
}

int do_action(){
	int retval, fd_input, fd_output;
	char *output_file;
	size_t output_len;
	const char *ext=".enc";
	
	if(Args.check == 1){
		output_len = strlen(Args.outputFilePath)+1;
		output_file = malloc(output_len);
		strcpy(output_file, Args.outputFilePath);
		output_file = (char *)realloc(output_file, output_len+5);
		strcat(output_file, ext);
		const char *path_to_output_file = (const char *)output_file;

		fd_input = open(Args.inputFilePath, O_RDONLY | O_NOFOLLOW);
		fd_output = open(path_to_output_file, O_WRONLY | O_NOFOLLOW | O_CREAT, 0644);
		if(fd_input == -1 || fd_output == -1){
			fprintf(stderr, _("main (encrypt): %s\n"), strerror(errno));
			free(output_file);
			return -1;
		}
		close(fd_input);
		close(fd_output);
		retval = encrypt_file(Args.inputFilePath, path_to_output_file);
		if(retval == -1){
			fprintf(stderr, _("main: error during file encryption\n"));
			remove(path_to_output_file);
			free(output_file);
			return -1;
		}
		free(output_file);
	}
	else if(Args.check == 2){
		fd_input = open(Args.inputFilePath, O_RDONLY | O_NOFOLLOW);
		fd_output = open(Args.outputFilePath, O_WRONLY | O_NOFOLLOW | O_CREAT, 0644);
		if(fd_input == -1 || fd_output == -1){
			fprintf(stderr, _("main (decrypt): %s\n"), strerror(errno));
			return -1;
		}
		close(fd_input);
		close(fd_output);
		retval = decrypt_file(Args.inputFilePath, Args.outputFilePath);
		if(retval == -1){
			printf(_("main: error during file decryption\n"));
			remove(Args.outputFilePath);
			return -1;
		}
	}
	else if(Args.check == 3){
		if(strcmp(Args.algo, "md5") == 0){
			compute_md5(Args.inputFilePath);
			return 0;
		}
		if(strcmp(Args.algo, "sha1") == 0){
			compute_sha1(Args.inputFilePath);
			return 0;
		}
		if(strcmp(Args.algo, "sha256") == 0){
			compute_sha256(Args.inputFilePath);
			return 0;
		}
		if(strcmp(Args.algo, "sha512") == 0){
			compute_sha512(Args.inputFilePath);
			return 0;
		}
		if(strcmp(Args.algo, "whirlpool") == 0){
			compute_whirlpool(Args.inputFilePath);
			return 0;
		}
		if(strcmp(Args.algo, "all") == 0){
			compute_md5(Args.inputFilePath);
			compute_sha1(Args.inputFilePath);
			compute_sha256(Args.inputFilePath);
			compute_sha512(Args.inputFilePath);
			compute_whirlpool(Args.inputFilePath);
			return 0;
		}
		else printf(_("--> Available hash algo are: md5, sha1, sha256, sha512 and whirlpool\n"));
	}
	return 0;
}
