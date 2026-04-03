#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GTKCRYPTO_TYPE_FILE_CRYPTO_PAGE (gtkcrypto_file_crypto_page_get_type ())
G_DECLARE_FINAL_TYPE (GtkcryptoFileCryptoPage, gtkcrypto_file_crypto_page, GTKCRYPTO, FILE_CRYPTO_PAGE, GtkBox)

GtkcryptoFileCryptoPage *gtkcrypto_file_crypto_page_new (void);

G_END_DECLS
