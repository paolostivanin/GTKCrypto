#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#define BUF_FILE 16777216 /* 16 MiB memory buffer (hash) */
#define BUFSIZE 2097152  /* 2 MiB memory buffer (delete_input_file) */

#define GCRYPT_MIN_VER "1.5.0"
#define VERSION "2.2.0-beta2"

#define HEADERBAR_BUF 22 /* buffer for the title of the headerbar */

#define DECRYPT 0
#define ENCRYPT 1

#define LOCALE_DIR "/usr/share/locale"
#define PACKAGE    "polcrypt"          // mo file name in LOCALE_DIR

#include <glib.h>
#include <gtk/gtk.h>

struct metadata_t{
	gint8 algo_type; //(NULL|0=aes),(1=serpent),(2=twofish),(3=camellia)
	gint8 algo_mode; //1=CBC,2=CTR
	guchar salt[32];
	guchar iv[16];
};
extern struct metadata_t Metadata;

struct widget_t{
	gchar *filename;
	GtkWidget *mainwin;
	GtkWidget *pwdEntry[2];
	GtkWidget *menu, *popover;
	GtkWidget *radioButton[6];
};
extern struct widget_t Widget;

struct hashWidget_t{
	gchar *filename;
	GtkWidget *hashEntry[8]; //md5, sha1, sha256, sha3-256, sha512, sha3-512, whir, gostr
	GtkWidget *hashCheck[8]; //md5, sha1, sha256, sha3-256, sha512, sha3-512, whir, gostr
};
extern struct hashWidget_t HashWidget;

#endif
