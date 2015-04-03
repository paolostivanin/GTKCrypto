#ifndef POLCRYPT_H_INCLUDED		
#define POLCRYPT_H_INCLUDED		
		
#define BUF_FILE 16777216 /* 16 MiB memory buffer (hash) */		
#define BUFSIZE 2097152  /* 2 MiB memory buffer (delete_input_file) */		
		
#define VERSION "3.0-beta.3"		
		
#define LOCALE_DIR "/usr/share/locale"		
#define PACKAGE    "polcrypt"          /* mo file name in LOCALE_DIR */		
		
#include <glib.h>		
#include <gtk/gtk.h>		
		
		
goffset get_file_size (const gchar *);		
gint check_pwd (GtkWidget *, GtkWidget *);		
void error_dialog (const gchar *, GtkWidget *);		
		
		
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
	gboolean hmac_error;		
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
	gint n_bit; //number of hash bit (256, 384, 512)
	gboolean gth_created[10];
	gchar *filename;	
	GHashTable *hash_table;		
	GtkWidget *hash_entry[10]; //md5, gost, sha1, sha256, sha3-256, sha384, sha3_384, sha512, sha3-512, whir		
	GtkWidget *hash_check[10]; //md5, gost, sha1, sha256, sha3-256, sha384, sha3_384, sha512, sha3-512, whir		
	gchar *key[10];
	struct threads_list
	{
		GThread *gth[10];
	} threads;
		
};		
extern struct hash_vars hash_var;		
		
#endif
