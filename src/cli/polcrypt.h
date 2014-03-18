#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#define BUF_FILE 16777216 /* 16 MiB memory buffer (hash) */
#define BUFSIZE 1048576  /* 1 MiB memory buffer (delete_input_file) */
#define GCRYPT_MIN_VER "1.6.0"
#define VERSION "2.1.0-dev"
#define LOCALE_DIR "/usr/share/locale" // or your specification
#define PACKAGE    "polcrypt-cli"          // mo file name in LOCALE

#include <glib.h>

struct metadata_t{
	gint8 algo_type; //(NULL|0=aes),(1=serpent),(2=twofish),(3=camelia),(4=aes+two),(5=aes+serp),(6=two+serp),(7=aes+serp+two)
	guchar salt[32];
	guchar iv[16];
};
extern struct metadata_t Metadata;

struct argvArgs_t{
	gchar *inputFilePath;
	gchar *algo;
	gint check; //1 encrypt, 2 decrypt, 3 hash
};
extern struct argvArgs_t Args;

#endif
