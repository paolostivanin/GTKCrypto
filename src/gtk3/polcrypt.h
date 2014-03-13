#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#define BUF_FILE 16777216 /* 16 MiB memory buffer (hash) */
#define BUFSIZE 1048576  /* 1 MiB memory buffer (delete_input_file) */
#define GCRYPT_MIN_VER "1.5.0"
#define VERSION "2.1.0-dev"
#define LOCALE_DIR "/usr/share/locale" // or your specification
#define PACKAGE    "polcrypt"          // mo file name in LOCALE

#include <glib.h>
#include <gtk/gtk.h>

struct metadata_t{
	unsigned char algo_type[16]; //aes,twofish,serpent,aes-two,aes-ser,aes-two-ser
	unsigned char salt[32];
	unsigned char iv[16];
};
extern struct metadata_t Metadata;

struct widget_t{
	gint mode, toEnc;
	gchar *filename;
	GtkWidget *pwdEntry, *pwdReEntry, *mainwin, *dialog, *file_dialog, *infobar, *infolabel;
};
extern struct widget_t Widget;

struct hashWidget_t{
	GThread *t1, *t2, *t3, *t4, *t5, *t6, *t7;
	gchar *filename;
	GtkWidget *entryMD5, *entryS1, *entryS256, *entryS512, *entryWhir, *entryGOSTR, *entrySTRIBOG512;
	GtkWidget *checkMD5, *checkS1, *checkS256, *checkS512, *checkWhir, *checkGOSTR, *checkSTRIBOG512;
};
extern struct hashWidget_t HashWidget;

#endif
