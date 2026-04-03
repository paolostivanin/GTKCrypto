#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GTKCRYPTO_TYPE_TEXT_CRYPTO_PAGE (gtkcrypto_text_crypto_page_get_type ())
G_DECLARE_FINAL_TYPE (GtkcryptoTextCryptoPage, gtkcrypto_text_crypto_page, GTKCRYPTO, TEXT_CRYPTO_PAGE, GtkBox)

GtkcryptoTextCryptoPage *gtkcrypto_text_crypto_page_new (void);

G_END_DECLS
