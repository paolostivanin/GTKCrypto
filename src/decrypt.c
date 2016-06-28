#include <gtk/gtk.h>
#include <gcrypt.h>
#include "gtkcrypto.h"
#include "hash.h"
#include "crypt.h"


void
decrypt_file (const gchar *input_file_path, const gchar *pwd)
{
    GError *err = NULL;

    goffset file_size = get_file_size (input_file_path);
    if (file_size == -1) {
        return;
    }
    if (file_size < sizeof (Metadata) + SHA512_DIGEST_SIZE) {
        g_printerr ("The selected file is not encrypted.\n");
        return;
    }

    GFile *in_file = g_file_new_for_path (input_file_path);
    GFileInputStream *in_stream = g_file_read (in_file, NULL, &err);
    if (err != NULL) {
        g_printerr ("%s\n", err->message);
        // TODO
        return;
    }

    gchar *output_file_path;
    if (!g_str_has_suffix (input_file_path, ".enc")) {
        g_printerr ("The selected file may not be encrypted\n");
        output_file_path = g_strconcat (input_file_path, ".decrypted");
    }
    else {
        output_file_path = g_strndup (input_file_path, (gsize) g_utf8_strlen (input_file_path, -1) - 4); // remove .enc
    }
    GFile *out_file = g_file_new_for_path (output_file_path);
    GFileOutputStream *out_stream = g_file_append_to (out_file, G_FILE_CREATE_NONE, NULL, &err);
    if (err != NULL) {
        g_printerr ("%s\n", err->message);
        // TODO
        return;
    }

    Metadata *header_metadata = g_new0 (Metadata, 1);

    gssize rw_len = g_input_stream_read (G_INPUT_STREAM (in_stream), header_metadata, sizeof (Metadata), NULL, &err);
    if (rw_len == -1) {
        g_printerr ("%s\n", err->message);
        // TODO
        return;
    }

    guchar *original_hmac = g_malloc (SHA512_DIGEST_SIZE);
    g_seekable_seek (G_SEEKABLE (in_stream), file_size - sizeof (Metadata) - SHA512_DIGEST_SIZE, G_SEEK_CUR, NULL, &err);
    rw_len = g_input_stream_read (G_INPUT_STREAM (in_stream), original_hmac, SHA512_DIGEST_SIZE, NULL, &err);
    if (rw_len == -1) {
        g_printerr ("%s\n", err->message);
        // TODO
        return;
    }

    g_seekable_seek (G_SEEKABLE (in_stream), file_size - sizeof (Metadata), G_SEEK_SET, NULL, &err);
    // TODO compute and compare hmac
    // TODO decrypt (pay attention to iv size and algo mode


    g_object_unref(in_stream);
    g_object_unref(out_stream);
    g_free(header_metadata);
    g_free(output_file_path);
    g_free(original_hmac);
}