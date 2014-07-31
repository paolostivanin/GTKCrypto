#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#define BUF_FILE 16777216 /* 16 MiB memory buffer (hash) */
#define BUFSIZE 2097152  /* 2 MiB memory buffer (delete_input_file) */

#define GCRYPT_MIN_VER "1.5.0"
#define VERSION "3.0-beta"

#define HEADERBAR_BUF 19 /* buffer for the headerbar's title */

#define ENCRYPT 0
#define DECRYPT 1

#define LOCALE_DIR "/usr/share/locale"
#define PACKAGE    "polcrypt"          /* mo file name in LOCALE_DIR */

#include <glib.h>
#include <gtk/gtk.h>


struct metadata_t{
	gint8 algoType; //(NULL|0=aes),(1=serpent),(2=twofish),(3=camellia)
	gint8 algoMode; //1=CBC,2=CTR
	guint8 salt[32];
	guint8 iv[16];
};
extern struct metadata_t Metadata;

struct widget_t{
	gchar *filename;
	GtkWidget *mainwin;
	GtkWidget *pwdEntry[2];
	GtkWidget *menu, *popover;
	GtkWidget *radioButton[6]; //aes, serpent, twofish, camellia, cbc, ctr
};
extern struct widget_t Widget;

struct hashWidget_t{
	gchar *filename;
	GHashTable *hashTable;
	GtkWidget *hashEntry[8]; //md5, sha1, sha256, sha3-256, sha512, sha3-512, whir, gostr
	GtkWidget *hashCheck[8]; //md5, sha1, sha256, sha3-256, sha512, sha3-512, whir, gostr
	gchar *key[8];
};
extern struct hashWidget_t HashWidget;

#endif
