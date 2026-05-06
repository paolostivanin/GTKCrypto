#include <glib/gstdio.h>
#include "state.h"

#define STATE_GROUP_HASHES "hashes"

static GKeyFile *kf = NULL;
static gchar    *state_path = NULL;

static void
ensure_loaded (void)
{
    if (kf != NULL) return;

    kf = g_key_file_new ();
    state_path = g_build_filename (g_get_user_config_dir (), "gtkcrypto", "state.ini", NULL);

    /* Best-effort load; missing file is fine — we'll create it on first save. */
    g_key_file_load_from_file (kf, state_path, G_KEY_FILE_NONE, NULL);
}

static void
flush (void)
{
    g_autofree gchar *dir = g_path_get_dirname (state_path);
    g_mkdir_with_parents (dir, 0700);
    g_key_file_save_to_file (kf, state_path, NULL);
}

gboolean
state_get_hash_enabled (const gchar *algo_label, gboolean default_value)
{
    ensure_loaded ();

    g_autoptr(GError) err = NULL;
    gboolean v = g_key_file_get_boolean (kf, STATE_GROUP_HASHES, algo_label, &err);
    if (err != NULL) return default_value;
    return v;
}

void
state_set_hash_enabled (const gchar *algo_label, gboolean enabled)
{
    ensure_loaded ();
    g_key_file_set_boolean (kf, STATE_GROUP_HASHES, algo_label, enabled);
    flush ();
}
