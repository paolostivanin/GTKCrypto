#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#define BUF_FILE 16777216 /* 16 MiB memory buffer (hash) */
#define BUFSIZE 1048576  /* 1 MiB memory buffer (delete_input_file) */
#define GCRYPT_MIN_VER "1.6.0"
#define VERSION "2.1.0-dev"
#define LOCALE_DIR "/usr/share/locale" // or your specification
#define PACKAGE    "polcrypt"          // mo file name in LOCALE

#include <glib.h>
#include <gtk/gtk.h>

struct metadata_t{
	gint8 algo_type; //(NULL|0=aes),(1=serpent),(2=twofish),(3=camellia),(4=aes+two),(5=aes+serp),(6=two+serp),(7=aes+serp+two)
	guchar salt[32];
	guchar iv[16];
};
extern struct metadata_t Metadata;

struct widget_t{
	gint mode, toEnc;
	gchar *filename;
	GtkWidget *pwdEntry, *pwdReEntry, *mainwin, *dialog, *file_dialog, *infobar, *infolabel, *combomenu;
};
extern struct widget_t Widget;

struct hashWidget_t{
	gchar *filename;
	GtkWidget *entryMD5, *entryS1, *entryS256, *entryS512, *entryWhir, *entryGOSTR, *entrySTRIBOG512;
	GtkWidget *checkMD5, *checkS1, *checkS256, *checkS512, *checkWhir, *checkGOSTR, *checkSTRIBOG512;
};
extern struct hashWidget_t HashWidget;

#endif
