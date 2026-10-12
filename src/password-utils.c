#include <gcrypt.h>
#include <math.h>
#include <string.h>

#include "password-utils.h"

static const gchar GENERATE_ALPHABET[] =
    "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+?";

guint
gtkcrypto_password_strength (const gchar *password)
{
    if (password == NULL || *password == '\0') {
        return 0;
    }

    gboolean lower = FALSE, upper = FALSE, digit = FALSE, symbol = FALSE,
             other = FALSE;
    gunichar seen[256];
    guint n_seen = 0;
    guint length = 0;

    for (const gchar *p = password; *p != '\0'; p = g_utf8_next_char (p)) {
        gunichar c = g_utf8_get_char (p);
        length++;
        if (c >= 'a' && c <= 'z') lower = TRUE;
        else if (c >= 'A' && c <= 'Z') upper = TRUE;
        else if (c >= '0' && c <= '9') digit = TRUE;
        else if (c < 128) symbol = TRUE;
        else other = TRUE;

        gboolean known = FALSE;
        for (guint i = 0; i < n_seen; i++) {
            if (seen[i] == c) {
                known = TRUE;
                break;
            }
        }
        if (!known && n_seen < G_N_ELEMENTS (seen)) {
            seen[n_seen++] = c;
        }
    }

    guint pool = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) +
                 (symbol ? 33 : 0) + (other ? 64 : 0);
    /* Repeated characters add little: weigh them at a quarter. */
    gdouble effective = n_seen + (length - n_seen) * 0.25;
    gdouble bits = effective * log2 ((gdouble)MAX (pool, 2));

    if (bits < 28) return 0;
    if (bits < 36) return 1;
    if (bits < 60) return 2;
    if (bits < 80) return 3;
    return 4;
}

gchar *
gtkcrypto_password_generate (guint length)
{
    const guint alphabet_len = sizeof GENERATE_ALPHABET - 1;
    /* Rejection sampling keeps the distribution uniform. */
    const guint limit = 256 - (256 % alphabet_len);

    gchar *out = g_malloc0 (length + 1);
    guint filled = 0;
    while (filled < length) {
        guint8 buf[64];
        gcry_randomize (buf, sizeof buf, GCRY_STRONG_RANDOM);
        for (gsize i = 0; i < sizeof buf && filled < length; i++) {
            if (buf[i] < limit) {
                out[filled++] = GENERATE_ALPHABET[buf[i] % alphabet_len];
            }
        }
        explicit_bzero (buf, sizeof buf);
    }
    return out;
}
