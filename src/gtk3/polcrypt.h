#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#define BUF_FILE 1048576 /* 1 MiB di memoria per il file come buffer massimo, poi spezzo (hash) */
#define BUFSIZE 24576  /* delete_input_file */
#define GCRYPT_MIN_VER "1.5.0"
#define VERSION "2.0.1-dev"
#define LOCALE_DIR "/usr/share/locale" // or your specification
#define PACKAGE    "polcrypt"          // mo file name in LOCALE

#include <glib.h>
#include <gtk/gtk.h>

struct metadata{
	unsigned char algo_type[16]; //aes,twofish,serpent,aes-two,aes-ser,aes-two-ser
	unsigned char salt[32];
	unsigned char iv[16];
};
extern struct metadata s_mdata;

struct info{
	gint mode, toEnc;
	gchar *filename;
	GtkWidget *pwdEntry, *pwdReEntry, *mainwin, *dialog, *file_dialog, *infobar, *infolabel;
};
extern struct info s_Info;

struct hashes{
	gchar *filename;
	GtkWidget *entryMD5, *entryS1, *entryS256, *entryS512, *entryWhir, *entryRMD;
	GtkWidget *checkMD5, *checkS1, *checkS256, *checkS512, *checkWhir, *checkRMD;
};
extern struct hashes s_HashType;

#endif
