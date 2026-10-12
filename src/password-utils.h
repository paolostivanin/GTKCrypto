#pragma once

#include <glib.h>

#define GTKCRYPTO_STRENGTH_MAX 4

/* Rough entropy-based rating: 0 (very weak) .. GTKCRYPTO_STRENGTH_MAX
 * (very strong). It is a hint for the user, not a security guarantee. */
guint   gtkcrypto_password_strength (const gchar *password);

/* Random password of LENGTH characters (letters, digits and a few symbols),
 * drawn uniformly from libgcrypt's strong RNG. Free with g_free(). */
gchar  *gtkcrypto_password_generate (guint length);
