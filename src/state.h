#pragma once

#include <glib.h>

gboolean state_get_hash_enabled (const gchar *algo_label, gboolean default_value);
void     state_set_hash_enabled (const gchar *algo_label, gboolean enabled);

/* Generic integer preferences (group "settings"). */
gint     state_get_int (const gchar *key, gint default_value);
void     state_set_int (const gchar *key, gint value);
