#include <gtk/gtk.h>
#include <gcrypt.h>
#include "crypt-common.h"
#include "hash.h"
#include "gtkcrypto.h"


guchar *
calculate_hmac (const gchar *file_path, const guchar *key, guchar *user_hmac)
{
    gsize mac_len = gcry_mac_get_algo_maclen (GCRY_MAC_HMAC_SHA3_512);

    guchar *hmac = g_try_malloc0 (mac_len);
    if (hmac == NULL) {
        g_printerr ("Unable to allocate enough memory for the HMAC\n");
        return NULL;
    }

    gcry_mac_hd_t mac;
    gcry_error_t err = gcry_mac_open (&mac, GCRY_MAC_HMAC_SHA3_512, 0, NULL);
    if (err) {
        g_printerr ("mac_open error: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
        return NULL;
    }

    err = gcry_mac_setkey (mac, key, HMAC_KEY_SIZE);
    if (err) {
        g_printerr ("mac_setkey error: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
        gcry_mac_close (mac);
        return NULL;
    }

    guchar *buf;
    goffset file_size = get_file_size (file_path);

    if (file_size < FILE_BUFFER) {
        buf = g_try_malloc0 (file_size);
    }
    else {
        buf = g_try_malloc0 (FILE_BUFFER);
    }
    if (buf == NULL) {
        g_printerr ("Error during memory allocation (hmac's buffer)\n");
        gcry_mac_close (mac);
        return NULL;
    }

    GError *gerr = NULL;
    GFile *file = g_file_new_for_path (file_path);
    GFileInputStream *istream = g_file_read (file, NULL, &gerr);
    if (gerr != NULL) {
        g_printerr ("%s\n", gerr->message);
        g_object_unref (file);
        gcry_mac_close (mac);
        g_free (buf);
        return NULL;
    }

    gssize read_len;
    goffset done_size = 0;
    while (done_size < file_size) {
        if ((file_size - done_size) < FILE_BUFFER) {
            read_len = g_input_stream_read (G_INPUT_STREAM (istream), buf, file_size - done_size, NULL, &gerr);
            if (read_len == -1) {
                g_printerr ("%s\n", gerr->message);
                return NULL;
            }
            err = gcry_mac_write (mac, buf, read_len);
            if (err) {
                g_printerr ("mac_write error: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
                gcry_mac_close (mac);
                g_free (buf);
                g_input_stream_close (G_INPUT_STREAM (istream), NULL, NULL);
                multiple_unref (2, (gpointer *) &file, (gpointer *) &istream);
                return NULL;
            }
            break;
        }
        else {
            read_len = g_input_stream_read (G_INPUT_STREAM (istream), buf, FILE_BUFFER, NULL, &gerr);
            if (read_len == -1) {
                g_printerr ("%s\n", gerr->message);
                return NULL;
            }
            err = gcry_mac_write (mac, buf, read_len);
        }
        if (err) {
            g_printerr ("mac_write error: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
            gcry_mac_close (mac);
            g_free (buf);
            g_input_stream_close (G_INPUT_STREAM (istream), NULL, NULL);
            multiple_unref (2, (gpointer *) &file, (gpointer *) &istream);
            return NULL;
        }
        done_size += FILE_BUFFER;
    }

    if (user_hmac != NULL) {
        err = gcry_mac_verify (mac, user_hmac, mac_len);
        gcry_mac_close (mac);
        g_free (buf);
        g_input_stream_close (G_INPUT_STREAM (istream), NULL, NULL);
        multiple_unref (2, (gpointer *) &file, (gpointer *) &istream);
        if (err) {
            g_printerr ("HMAC verification failed: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
            return HMAC_MISMATCH;
        }
        else {
            return HMAC_OK;
        }
    }
    else {
        err = gcry_mac_read (mac, hmac, &mac_len);
        if (err) {
            g_printerr ("mac_read error: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
            gcry_mac_close (mac);
            g_free (buf);
            g_input_stream_close (G_INPUT_STREAM (istream), NULL, NULL);
            multiple_unref (2, (gpointer *) &file, (gpointer *) &istream);
            return NULL;
        }
    }

    gcry_mac_close (mac);
    g_free (buf);
    g_input_stream_close (G_INPUT_STREAM (istream), NULL, NULL);
    multiple_unref (2, (gpointer *) &file, (gpointer *) &istream);

    return hmac;
}
