#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#define BUF_FILE 16777216 /* 16 MiB memory buffer (hash) */
#define BUFSIZE 1048576  /* 1 MiB memory buffer (delete_input_file) */
#define GCRYPT_MIN_VER "1.5.0"
#define VERSION "2.2.0-dev"
#define LOCALE_DIR "/usr/share/locale" // or your specification
#define PACKAGE    "polcrypt"          // mo file name in LOCALE

#include <glib.h>
#include <gtk/gtk.h>

struct metadata_t{
	gint8 algo_type; //(NULL|0=aes),(1=serpent),(2=twofish),(3=camellia)
	guchar salt[32];
	guchar iv[16];
};
extern struct metadata_t Metadata;

struct widget_t{
	gint error;
	gint mode, toEnc;
	gchar *filename;
	GtkWidget *pwdEntry, *pwdReEntry, *mainwin, *dialog, *file_dialog, *infobar, *infolabel;
	GtkWidget *menu;
	GtkWidget *popover;
	GtkWidget *r0, *r1, *r2, *r3, *r4;
};
extern struct widget_t Widget;

struct hashWidget_t{
	gchar *filename;
	GtkWidget *entryMD5, *entryS1, *entryS256, *entryS3_256, *entryS512, *entryS3_512, *entryWhir, *entryGOSTR;
	GtkWidget *checkMD5, *checkS1, *checkS256, *checkS3_256, *checkS512, *checkS3_512, *checkWhir, *checkGOSTR;
};
extern struct hashWidget_t HashWidget;

#endif
