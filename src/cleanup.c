#include <gtk/gtk.h>
#include <gcrypt.h>
#include "crypt-common.h"


void
crypto_keys_cleanup (CryptoKeys *encryption_keys)
{
    gcry_free (encryption_keys->derived_key);
    gcry_free (encryption_keys->crypto_key);
    gcry_free (encryption_keys->hmac_key);
    g_free (encryption_keys);
}


void
gfile_cleanup (GFile *ifile,
               GFile *ofile)
{
    g_object_unref(ifile);
    g_object_unref(ofile);
}


void
gstream_cleanup (GFileInputStream  *istream,
                 GFileOutputStream *ostream)
{
    if (istream != NULL) {
        g_input_stream_close (G_INPUT_STREAM (istream), NULL, NULL);
        g_object_unref (istream);
    }
    if (ostream != NULL) {
        g_output_stream_close (G_OUTPUT_STREAM (ostream), NULL, NULL);
        g_object_unref (ostream);
    }
}


void
data_cleanup (gpointer data1,
              gpointer data2,
              gpointer data3)
{
    g_free (data1);
    g_free (data2);
    g_free (data3);
}