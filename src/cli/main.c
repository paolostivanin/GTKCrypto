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
#include <glib.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "polcrypt.h"

int encrypt_file(struct argvArgs_t *);
int decrypt_file(struct argvArgs_t *);
void *compute_sha1(struct argvArgs_t *);
void *compute_sha256(struct argvArgs_t *);
void *compute_sha512(struct argvArgs_t *);
void *compute_md5(struct argvArgs_t *);
void *compute_whirlpool(struct argvArgs_t *);
void *compute_stribog512(struct argvArgs_t *);
void *compute_gostr(struct argvArgs_t *);
int do_action();

struct argvArgs_t Args;

GCRY_THREAD_OPTION_PTHREAD_IMPL;

int main(int argc, char **argv){
	if(argc == 1){
		printf(_("To encrypt a file: %s [--encrypt] <path-to-input_file> --algo <aes,twofish,serpent,camellia>\n"), argv[0]);
		printf(_("To decrypt a file: %s [--decrypt] <path-to-input_file>\n"), argv[0]);
		printf(_("To calculate one or more file hash: %s --hash <path-to-input_file> --algo [md5|sha1|sha256|sha512|whirlpool|all]\n"), argv[0]);
	}
	
	if(getuid() == 0){
		printf(_("You are root, please run this program as NORMAL USER!\n"));
		return 0;
	}
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	if(!gcry_check_version(GCRYPT_MIN_VER)){
		printf(_("libgcrypt min version required: 1.6.0\n"));
		return -1;
	}

	const gchar *glibVer = glib_check_version(2, 32, 0);
	if(glibVer != NULL){
		g_print("The required version of GLib is 2.32.0 or greater.\n");
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
		{"algo", required_argument, NULL, 'a'},
		{"hash", required_argument, NULL, 's'},
		{"type", required_argument, NULL, 't'},
		{NULL, 0, NULL, 0}
	};

	while ((ch = getopt_long(argc, argv, "v", long_options, NULL)) != -1){
			switch(ch){
			case 'v':
				printf(_("PolCrypt v%s developed by Paolo Stivanin <info@paolostivanin.com>\n"), VERSION);
				return 0;
			
			case 'h':
				printf(_("To encrypt|decrypt a file: %s [--encrypt] | [--decrypt] <path-to-input_file> --algo <aes,twofish,serpent,camellia>\n"), argv[0]);
				printf(_("To calculate one or more file hash: %s --hash <path-to-input_file> --type [md5|sha1|sha256|sha512|whirlpool|all]\n"), argv[0]);
				return 0;
			
			case '?':
				return -1;
			}
	}
	optind = 1;
	while ((ch = getopt_long(argc, argv, "e:d:s:t:o:", long_options, NULL)) != -1){
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
				do_action();
				free(Args.inputFilePath);
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
			
			case 't':
				if(Args.check != 3){
					printf(_("You must use the option --hash to use the option --algo\n"));
					return -1;
				}
				nameLen = strlen(optarg)+1;
				Args.algo = malloc(nameLen);
				if(Args.algo == NULL){
					fprintf(stderr, _("main (case t): error during memory allocation\n"));
					return -1;
				}
				strcpy(Args.algo, optarg);
				do_action();
				free(Args.inputFilePath);
				free(Args.algo);
				return 0;
				
			case 'a':
				if(Args.check != 1){
					printf(_("You must use the option --encrypt to use the option --algo\n"));
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
			
			case '?':
				fprintf(stderr, _("Unknown option\n"));
				return -1;
		}
	}
	return 0;
}

int do_action(){
	if(Args.check == 1){
		encrypt_file(&Args);
	}
	else if(Args.check == 2){
		decrypt_file(&Args);
	}
	else if(Args.check == 3){
		if(strcmp(Args.algo, "md5") == 0){
			compute_md5(&Args);
			return 0;
		}
		if(strcmp(Args.algo, "sha1") == 0){
			compute_sha1(&Args);
			return 0;
		}
		if(strcmp(Args.algo, "sha256") == 0){
			compute_sha256(&Args);
			return 0;
		}
		if(strcmp(Args.algo, "sha512") == 0){
			compute_sha512(&Args);
			return 0;
		}
		if(strcmp(Args.algo, "whirlpool") == 0){
			compute_whirlpool(&Args);
			return 0;
		}
		if(strcmp(Args.algo, "all") == 0){
			GThread *t1, *t2, *t3, *t4, *t5, *t6, *t7;
			t1 = g_thread_new("t1", (GThreadFunc)compute_md5, &Args);
			t2 = g_thread_new("t2", (GThreadFunc)compute_sha1, &Args);
			t3 = g_thread_new("t3", (GThreadFunc)compute_sha256, &Args);
			t4 = g_thread_new("t4", (GThreadFunc)compute_sha512, &Args);
			t5 = g_thread_new("t5", (GThreadFunc)compute_whirlpool, &Args);
			t6 = g_thread_new("t6", (GThreadFunc)compute_gostr, &Args);
			t7 = g_thread_new("t7", (GThreadFunc)compute_stribog512, &Args);
			g_thread_join(t1);
			g_thread_join(t2);
			g_thread_join(t3);
			g_thread_join(t4);
			g_thread_join(t5);
			g_thread_join(t6);
			g_thread_join(t7);
			return 0;
		}
		else printf(_("--> Available hash algo are: md5, sha1, sha256, sha512, gostr, stribog512 and whirlpool\n"));
	}
	return 0;
}
