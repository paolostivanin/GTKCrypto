#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GTKCRYPTO_TYPE_HASHING_PAGE (gtkcrypto_hashing_page_get_type ())
G_DECLARE_FINAL_TYPE (GtkcryptoHashingPage, gtkcrypto_hashing_page, GTKCRYPTO, HASHING_PAGE, GtkBox)

GtkcryptoHashingPage *gtkcrypto_hashing_page_new (void);

G_END_DECLS
