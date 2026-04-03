#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GTKCRYPTO_TYPE_APPLICATION (gtkcrypto_application_get_type ())
G_DECLARE_FINAL_TYPE (GtkcryptoApplication, gtkcrypto_application, GTKCRYPTO, APPLICATION, AdwApplication)

GtkcryptoApplication *gtkcrypto_application_new (void);

G_END_DECLS
