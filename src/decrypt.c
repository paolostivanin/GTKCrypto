#include <gtk/gtk.h>
#include <gcrypt.h>
#include "gtkcrypto.h"
#include "hash.h"
#include "crypt.h"


static GFile *get_g_file_with_encrypted_data (GFileInputStream *, goffset);

static gboolean compare_hmac (guchar *original_hamc, GFile *encrypted_data);


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

    g_seekable_seek (G_SEEKABLE (in_stream), sizeof (Metadata), G_SEEK_SET, NULL, &err);
    GFile *file_encrypted_data = get_g_file_with_encrypted_data (in_stream, file_size);
    if (file_encrypted_data == NULL) {
        return;
    }

    if (!compare_hmac (original_hmac, file_encrypted_data)) {
        return;
    }
    // TODO decrypt (pay attention to iv size and algo mode)

    g_object_unref (file_encrypted_data);
    g_object_unref(in_stream);
    g_object_unref(out_stream);
    g_free(header_metadata);
    g_free(output_file_path);
    g_free(original_hmac);
}


static GFile *
get_g_file_with_encrypted_data (GFileInputStream *in_stream, goffset file_size)
{
    GError *err = NULL;
    GFileIOStream *ostream;
    gssize rw_len;
    guchar *buf;
    gsize len_file_data = file_size - sizeof (Metadata) - SHA512_DIGEST_SIZE;
    gsize done_size = 0;

    GFile *tmp_encrypted_file = g_file_new_tmp (NULL, &ostream, &err);
    if (tmp_encrypted_file == NULL) {
        g_printerr ("%s\n", err->message);
        // TODO
        return NULL;
    }

    GFileOutputStream *out_enc_stream = g_file_append_to (tmp_encrypted_file, G_FILE_CREATE_NONE, NULL, &err);
    if (out_enc_stream == NULL) {
        g_printerr ("%s\n", err->message);
        // TODO
        return NULL;
    }

    if (file_size < FILE_BUFFER) {
        buf = g_malloc (len_file_data);
        g_input_stream_read (G_INPUT_STREAM (in_stream), buf, len_file_data, NULL, &err);
        g_output_stream_write (G_OUTPUT_STREAM (out_enc_stream), buf, len_file_data, NULL, &err);
    }
    else {
        buf = g_malloc (FILE_BUFFER);
        while (done_size < len_file_data) {
            if ((len_file_data - done_size) > FILE_BUFFER) {
                rw_len = g_input_stream_read (G_INPUT_STREAM (in_stream), buf, FILE_BUFFER, NULL, &err);
            }
            else {
                rw_len = g_input_stream_read (G_INPUT_STREAM (in_stream), buf, file_size - done_size, NULL, &err);
            }
            if (rw_len == -1) {
                g_printerr ("%s\n", err->message);
                // TODO
                return NULL;
            }
            g_output_stream_write (G_OUTPUT_STREAM (out_enc_stream), buf, rw_len, NULL, &err);
            done_size += rw_len;
            memset (buf, 0, FILE_BUFFER);
        }
    }

    g_output_stream_close (G_OUTPUT_STREAM (out_enc_stream), NULL, NULL);
    g_object_unref (out_enc_stream);
    g_free (buf);

    return tmp_encrypted_file;
}


static gboolean
compare_hmac (guchar *hmac, GFile *fl) {
    gchar *path = g_file_get_path (fl);

    guchar *computed_hmac = calculate_hmac (path, hmac_key, HMAC_KEY_SIZE);

    multiple_free (2, (gpointer *) &path, (gpointer *) &computed_hmac);
}