#include <gtk/gtk.h>
#include <gcrypt.h>
#include "gtkcrypto.h"
#include "hash.h"
#include "crypt.h"


void
decrypt_file (const gchar *input_file_path, const gchar *pwd)
{
    GError *err = NULL;

    GFile *in_file = g_file_new_for_path (input_file_path);
    GFileInputStream *in_stream = g_file_read (in_file, NULL, &err);
    if (err != NULL) {
        g_printerr ("%s\n", err->message);
        // TODO
        return;
    }

    gchar *output_file_path = g_strconcat (input_file_path, ".enc", NULL);
    GFile *out_file = g_file_new_for_path (output_file_path);
    GFileOutputStream *out_stream = g_file_append_to (out_file, G_FILE_CREATE_NONE, NULL, &err);
    if (err != NULL) {
        g_printerr ("%s\n", err->message);
        // TODO
        return;
    }
}