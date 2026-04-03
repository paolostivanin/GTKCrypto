#pragma once

#include <glib.h>

gpointer encrypt_file (const gchar *input_file_path, const gchar *pwd, const gchar *algo, const gchar *algo_mode);
