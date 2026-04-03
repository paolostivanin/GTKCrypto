#pragma once

#include <glib.h>
#include <gio/gio.h>

gchar      *get_file_hash       (const gchar *file_path, gint hash_algo, gint digest_size);

goffset     get_file_size       (const gchar *file_path);
