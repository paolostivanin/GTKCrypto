#ifndef POLCRYPT_H_INCLUDED		
#define POLCRYPT_H_INCLUDED		
		
#define BUF_FILE 16777216 /* 16 MiB memory buffer (hash) */		
#define BUFSIZE 2097152  /* 2 MiB memory buffer (delete_input_file) */

#define MD5_DIGEST_SIZE 16
#define SHA1_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32
#define GOST94_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64
#define WHIRLPOOL_DIGEST_SIZE 64

#define VERSION "3.0-beta.5"
		
#define LOCALE_DIR "/usr/share/locale"		
#define PACKAGE    "polcrypt"          /* mo file name in LOCALE_DIR */		
		
#include <glib.h>		
#include <gtk/gtk.h>		
		
		
goffset get_file_size (const gchar *);		
gint check_pwd (GtkWidget *, GtkWidget *);		
void error_dialog (const gchar *, GtkWidget *);	
gboolean start_entry_progress (gpointer);	
gboolean stop_entry_progress (gpointer);
gboolean stop_btn (gpointer);
gboolean start_btn (gpointer);
gboolean delete_entry_text (gpointer);
gpointer launch_thread (gpointer, gpointer);
		
		
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
    GSList *filenames;
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
	gulong sig[10];
	GtkWidget *mainwin;
    GtkWidget *dialog;
	gchar *filename;	
	GHashTable *hash_table;
	GThreadPool *pool;	
	GtkWidget *hash_entry[10]; //md5, gost, sha1, sha256, sha3-256, sha384, sha3_384, sha512, sha3-512, whir		
	GtkWidget *hash_check[10]; //md5, gost, sha1, sha256, sha3-256, sha384, sha3_384, sha512, sha3-512, whir	
	gchar *key[10];
};		
extern struct hash_vars hash_var;


struct IdleData
{
    GtkWidget *dialog;
	GtkWidget *entry;
	GtkWidget *check;
	GHashTable *hash_table;
	gchar *key;
};
extern struct IdleData func_data;
		
#endif
