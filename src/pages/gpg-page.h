#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GTKCRYPTO_TYPE_GPG_PAGE (gtkcrypto_gpg_page_get_type ())
G_DECLARE_FINAL_TYPE (GtkcryptoGpgPage, gtkcrypto_gpg_page, GTKCRYPTO, GPG_PAGE, GtkBox)

GtkcryptoGpgPage *gtkcrypto_gpg_page_new (void);

G_END_DECLS
