#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

struct metadata{
	gchar header[32];
	guchar salt[32];
	guchar iv[16];
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
unsigned char *calculate_hmac(const gchar *, const guchar *key, gsize, gint);
int random_write(gint, gint, gsize);
int zero_write(gint, gsize);
int check_pkcs7(guchar *, guchar *);

#endif
