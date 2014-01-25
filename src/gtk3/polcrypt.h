#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

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
int secure_file_delete();
unsigned char *calculate_hmac(const char *, const unsigned char *key, size_t, int);
int random_write(int, int, size_t);
int zero_write(int, size_t);
int check_pkcs7(guchar *, guchar *);

#endif
