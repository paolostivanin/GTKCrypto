#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#include <glib.h>
#include <gtk/gtk.h>

struct metadata{
	unsigned char salt[32];
	unsigned char iv[16];
};
extern struct metadata s_mdata;

struct info{
	gint mode, isSignalActivate;
	gchar *filename;
	GtkWidget *pwdEntry, *pwdReEntry, *mainwin, *dialog;
};
extern struct info s_Info;

int encrypt_file_gui(struct info *);
int decrypt_file_gui(struct info *);
int delete_input_file(struct info *, size_t);
unsigned char *calculate_hmac(const char *, const unsigned char *key, size_t, int);
int random_write(int, int, size_t, int);
int zero_write(int, size_t, int);
int check_pkcs7(unsigned char *, unsigned char *);

#endif
