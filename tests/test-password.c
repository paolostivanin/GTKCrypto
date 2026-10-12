#include <glib.h>
#include <gcrypt.h>
#include <string.h>

#include "password-utils.h"

static void
test_strength_ordering (void)
{
    g_assert_cmpuint (gtkcrypto_password_strength (NULL), ==, 0);
    g_assert_cmpuint (gtkcrypto_password_strength (""), ==, 0);
    g_assert_cmpuint (gtkcrypto_password_strength ("aaaaaaaa"), ==, 0);
    g_assert_cmpuint (gtkcrypto_password_strength ("password"), <=, 1);
    g_assert_cmpuint (gtkcrypto_password_strength ("Tr0ub4dor&3"), >=, 2);
    g_assert_cmpuint (gtkcrypto_password_strength (
                          "correct horse battery staple 9!"), ==,
                      GTKCRYPTO_STRENGTH_MAX);
    g_assert_cmpuint (gtkcrypto_password_strength ("pässwörd-ünïcode-ok"), >=, 3);
}

static void
test_generate (void)
{
    for (guint len = 1; len <= 64; len += 7) {
        g_autofree gchar *pwd = gtkcrypto_password_generate (len);
        g_assert_cmpuint (strlen (pwd), ==, len);
        for (const gchar *p = pwd; *p; p++) {
            g_assert_true ((guchar)*p > 32 && (guchar)*p < 127);
        }
    }
    g_autofree gchar *a = gtkcrypto_password_generate (24);
    g_autofree gchar *b = gtkcrypto_password_generate (24);
    g_assert_cmpstr (a, !=, b);
    g_assert_cmpuint (gtkcrypto_password_strength (a), ==,
                      GTKCRYPTO_STRENGTH_MAX);
}

int
main (int argc, char **argv)
{
    g_test_init (&argc, &argv, NULL);
    g_assert_nonnull (gcry_check_version ("1.10.1"));
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    g_test_add_func ("/password/strength", test_strength_ordering);
    g_test_add_func ("/password/generate", test_generate);
    return g_test_run ();
}
