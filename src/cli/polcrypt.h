#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#define BUF_FILE 16777216 /* 16 MiB memory buffer (hash) */
#define BUFSIZE 1048576  /* 1 MiB memory buffer (delete_input_file) */
#define GCRYPT_MIN_VER "1.6.0"
#define VERSION "2.1.0-dev"
#define LOCALE_DIR "/usr/share/locale" // or your specification
#define PACKAGE    "polcrypt-cli"          // mo file name in LOCALE

struct metadata_t{
	unsigned char algo_type[16]; //aes,twofish,serpent,aes-two,aes-ser,aes-two-ser
	unsigned char salt[32];
	unsigned char iv[16];
};
extern struct metadata_t Metadata;

struct argvArgs_t{
	char *inputFilePath;
	char *outputFilePath;
	char *algo;
	int check; //1 encrypt, 2 decrypt, 3 hash
};
extern struct argvArgs_t Args;

#endif
