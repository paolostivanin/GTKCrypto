#pragma once

#include "gtkcrypto-application.h"

G_BEGIN_DECLS

#define GTKCRYPTO_TYPE_WINDOW (gtkcrypto_window_get_type ())
G_DECLARE_FINAL_TYPE (GtkcryptoWindow, gtkcrypto_window, GTKCRYPTO, WINDOW, AdwApplicationWindow)

GtkcryptoWindow *gtkcrypto_window_new (GtkcryptoApplication *app);

G_END_DECLS
