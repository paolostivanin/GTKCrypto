#include <gtk/gtk.h>
#include <gcrypt.h>
#include "crypt-common.h"
#include "hash.h"
#include "gtkcrypto.h"


guchar *
calculate_hmac (const gchar *file_path, const guchar *key, gsize keylen)
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
        fprintf(stderr, "mac_setkey error: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
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
    // TODO g input stream read to buf
    goffset done_size = 0;
    while (done_size < file_size) {
        if ((file_size - done_size) < FILE_BUFFER) {
            err = gcry_mac_write (mac, buf, file_size - done_size);
            if (err) {
                g_printerr ("mac_write error: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
                gcry_mac_close (mac);
                g_free (buf);
                return NULL;
            }
            break;
        }
        else {
            err = gcry_mac_write (mac, buf, FILE_BUFFER);
        }
        if (err) {
            g_printerr ("mac_write error: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
            gcry_mac_close (mac);
            g_free (buf);
            return NULL;
        }
        done_size += FILE_BUFFER;
    }

    err = gcry_mac_read (mac, hmac, &mac_len);
    if (err) {
        g_printerr ("mac_read error: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
        gcry_mac_close (mac);
        g_free (buf);
        return NULL;
    }

    gcry_mac_close (mac);
    g_free (buf);

    return hmac;
}
