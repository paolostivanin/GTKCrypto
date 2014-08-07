#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#define BUF_FILE 16777216 /* 16 MiB memory buffer (hash) */
#define BUFSIZE 2097152  /* 2 MiB memory buffer (delete_input_file) */

#define GCRYPT_MIN_VER "1.5.0"
#define VERSION "3.0-beta.2"

#define HEADERBAR_BUF 21 /* buffer for the headerbar's title */

#define LOCALE_DIR "/usr/share/locale"
#define PACKAGE    "polcrypt"          /* mo file name in LOCALE_DIR */

#include <glib.h>
#include <gtk/gtk.h>


struct data
{
	gint8 algo_type; //(NULL|0=aes),(1=serpent),(2=twofish),(3=camellia)
	gint8 block_cipher_mode; //1=CBC,2=CTR
	guint8 salt[32];
	guint8 iv[16];
};
extern struct data metadata;

struct main_vars
{
	gboolean encrypt; //TRUE := enc, FALSE := dec
	gchar *filename;
	GtkWidget *main_window;
	GtkWidget *pwd_entry[2];
	GtkWidget *menu, *popover;
	GtkWidget *radio_button[6]; //aes, serpent, twofish, camellia, cbc, ctr
	GtkWidget *bar_dialog;
	GtkWidget *pBar;
};
extern struct main_vars main_var;

struct hash_vars
{
	gchar *filename;
	GHashTable *hash_table;
	GtkWidget *hash_entry[8]; //md5, sha1, sha256, sha3-256, sha512, sha3-512, whir, gostr
	GtkWidget *hash_check[8]; //md5, sha1, sha256, sha3-256, sha512, sha3-512, whir, gostr
	gchar *key[8];
};
extern struct hash_vars hash_var;

struct text_vars
{
	GtkWidget *dialog;
	GtkWidget *text_view;
	GtkWidget *pwd[2];	
	GtkTextBuffer *buffer;
	gchar *text;
	guchar *crypt_text;
	gchar *decoded_text;
	gsize total_length;
	gsize out_length;
	gint8 action;
};
extern struct text_vars text_var;

#endif
