#pragma once

#include "crypt-common.h"

gboolean gtkcrypto_decrypt_file (const gchar *input_path,
                                 const gchar *output_path,
                                 const guint8 *password,
                                 gsize password_len,
                                 gboolean overwrite,
                                 GCancellable *cancellable,
                                 GError **error);

/* Compatibility wrapper for the current GUI while it is migrated. */
gpointer decrypt_file (const gchar *input_file_path, const gchar *pwd);
