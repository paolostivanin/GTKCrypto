#include <glib.h>

gboolean file_has_extension (const gchar *file_path, const gchar *ext)
{
    gchar *last_occurence = g_strrstr (file_path, ext);

    if (last_occurence != NULL && *(last_occurence + g_utf8_strlen (ext, -1)) == '\0')
        return TRUE;
    else
        return FALSE;
}
