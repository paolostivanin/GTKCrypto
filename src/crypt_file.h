#ifndef CRYPT_FILE_H_INCLUDED
#define CRYPT_FILE_H_INCLUDED

#include <glib.h>
#include <gtk/gtk.h>

guchar *calculate_hmac (const gchar *, const guchar *, gsize, gsize);
gint delete_input_file (const gchar *, gsize);
gint check_pkcs7 (guchar *, guchar *);

#endif
