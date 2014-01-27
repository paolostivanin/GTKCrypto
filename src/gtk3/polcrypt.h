#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#include <glib.h>
#include <gtk/gtk.h>
#define BUF_FILE 1048576 /* 1 MiB di memoria per il file come buffer massimo, poi spezzo */
#define GCRYPT_MIN_VER "1.5.0"

struct metadata{
	unsigned char salt[32];
	unsigned char iv[16];
};
extern struct metadata s_mdata;

struct info{
	gint mode, isSignalActivate;
	gchar *filename;
	GtkWidget *pwdEntry, *pwdReEntry, *mainwin, *dialog, *file_dialog;
};
extern struct info s_Info;

struct hashes{
	gchar *filename;
	GtkWidget *entryMD5, *entryS1, *entryS256, *entryS512, *entryWhir, *entryRMD;
	GtkWidget *checkMD5, *checkS1, *checkS256, *checkS512, *checkWhir, *checkRMD;
};
extern struct hashes s_HashType;

int encrypt_file_gui(struct info *);
int decrypt_file_gui(struct info *);
int delete_input_file(struct info *, size_t);
unsigned char *calculate_hmac(const char *, const unsigned char *key, size_t, int);
int random_write(int, int, size_t, int);
int zero_write(int, size_t, int);
int check_pkcs7(unsigned char *, unsigned char *);
int compute_md5(struct hashes *);
int compute_sha1(struct hashes *);
int compute_sha256(struct hashes *);
int compute_sha512(struct hashes *);
int compute_whirlpool(struct hashes *);
int compute_rmd160(struct hashes *);

#endif
