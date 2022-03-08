#include <gtk/gtk.h>
#include <gpgme.h>
#include <locale.h>
#include <glib/gstdio.h>
#include "gpgme-misc.h"


static void init_gpgme  (void);

static void cleanup     (FILE               *f1,
                         GFile              *f2,
                         GFileOutputStream  *ostream,
                         gchar              *buf,
                         gpgme_key_t        *sk,
                         gpgme_ctx_t        *ctx);


gpointer
sign_file (const gchar *input_file_path,
           const gchar *fpr)
{
    gpgme_ctx_t context;

    gpgme_error_t error = gpgme_new (&context);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        return GPGME_ERROR;
    }

    gpgme_set_armor (context, 0);

    error = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        gpgme_release (context);
        return GPGME_ERROR;
    }

    const char *keyring_dir = gpgme_get_dirinfo ("homedir");
    error = gpgme_ctx_set_engine_info (context, GPGME_PROTOCOL_OpenPGP, NULL, keyring_dir);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        gpgme_release (context);
        return GPGME_ERROR;
    }

    gpgme_key_t signing_key;
    error = gpgme_get_key (context, fpr, &signing_key, 1);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        gpgme_release (context);
        return GPGME_ERROR;
    }

    error = gpgme_signers_add (context, signing_key);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        cleanup (NULL, NULL, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    FILE *infp = g_fopen (input_file_path, "r");
    if (infp == NULL) {
        g_printerr ("Couldn't open input file\n");
        cleanup (NULL, NULL, NULL, NULL, &signing_key, &context);
        return FILE_OPEN_ERROR;
    }

    gpgme_data_t clear_text;
    error = gpgme_data_new_from_stream (&clear_text, infp);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        cleanup (infp, NULL, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    gpgme_data_t signed_text;
    error = gpgme_data_new (&signed_text);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        cleanup (infp, NULL, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    error = gpgme_op_sign (context, clear_text, signed_text, GPGME_SIG_MODE_DETACH);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        cleanup (infp, NULL, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    gpgme_sign_result_t result = gpgme_op_sign_result (context);
    if (result->invalid_signers) {
        g_printerr ("Invalid signer found: %s\n", result->invalid_signers->fpr);
        cleanup (infp, NULL, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }
    if (!result->signatures || result->signatures->next) {
        g_printerr ("Unexpected number of signatures created\n");
        cleanup (infp, NULL, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    if (gpgme_data_seek (signed_text, 0, SEEK_SET) == -1) {
        g_printerr ("gpgme_data_seek error\n");
        cleanup (infp, NULL, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    gchar *buffer = g_try_malloc0 (SIG_MAXLEN);
    if (buffer == NULL) {
        g_printerr ("Couldn't allocate memory\n");
        cleanup (infp, NULL, NULL, NULL, &signing_key, &context);
        return MEMORY_ALLOCATION_ERROR;
    }

    gssize nbytes = gpgme_data_read (signed_text, buffer, SIG_MAXLEN);
    if (nbytes == -1) {
        g_printerr ("Error while reading data\n");
        cleanup (infp, NULL, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    GError *gerr = NULL;
    gchar *output_file_path = g_strconcat (input_file_path, ".sig", NULL);
    GFile *fpout = g_file_new_for_path (output_file_path);
    GFileOutputStream *ostream = g_file_append_to (fpout, G_FILE_CREATE_REPLACE_DESTINATION, NULL, &gerr);
    if (gerr != NULL) {
        g_printerr ("Couldn't open output file for writing\n");
        cleanup (infp, fpout, NULL, output_file_path, &signing_key, &context);
        g_clear_error (&gerr);
        return FILE_OPEN_ERROR;
    }

    gssize wbytes = g_output_stream_write (G_OUTPUT_STREAM (ostream), buffer, (gsize)nbytes, NULL, &gerr);
    if (wbytes == -1) {
        g_printerr ("Couldn't write the request number of bytes (%s)\n", gerr->message);
        cleanup (infp, fpout, ostream, output_file_path, &signing_key, &context);
        return FILE_WRITE_ERROR;
    }

    cleanup (infp, fpout, ostream, output_file_path, &signing_key, &context);

    return SIGN_OK;
}


GSList *
get_available_keys ()
{
    init_gpgme ();

    gpgme_ctx_t ctx;
    gpgme_key_t key;

    gpgme_error_t  err = gpgme_new (&ctx);
    if (err) {
        g_printerr ("%s: %s\n", gpgme_strsource (err), gpgme_strerror (err));
        return GPGME_ERROR;
    }

    err = gpgme_op_keylist_start (ctx, NULL, 1);
    if (err) {
        g_printerr ("%s: %s\n", gpgme_strsource (err), gpgme_strerror (err));
        gpgme_release (ctx);
        return GPGME_ERROR;
    }

    GSList *list = NULL;
    KeyInfo *key_info;

    key_info = g_new0 (KeyInfo, 1);
    while (1) {
        err = gpgme_op_keylist_next (ctx, &key);
        if (err) {
            break;
        }
        key_info->key_id = g_strdup (key->subkeys->keyid);
        if (key->uids && key->uids->name) {
            key_info->name = g_strdup (key->uids->name);
        } else {
            key_info->name = g_strdup ("none");
        }
        if (key->uids && key->uids->email) {
            key_info->email = g_strdup (key->uids->email);
        } else {
            key_info->email = g_strdup ("none");
        }
        key_info->key_fpr = g_strdup (key->subkeys->fpr);

        gssize bytes_to_copy = (gssize)sizeof(KeyInfo) + g_utf8_strlen (key_info->name, -1) + g_utf8_strlen (key_info->email, -1) +
                g_utf8_strlen (key_info->key_id, -1) + g_utf8_strlen (key_info->key_fpr, -1) + 4;

        list = g_slist_append (list, g_memdupX (key_info, (guint)bytes_to_copy));

        g_free (key_info->key_id);
        g_free (key_info->name);
        g_free (key_info->email);
        g_free (key_info->key_fpr);

        gpgme_key_release (key);
    }

    g_free (key_info);
    gpgme_release (ctx);

    return list;
}


gpointer
verify_signature (const gchar *signed_file_path,
                  const gchar *detached_signature_path)
{
    init_gpgme ();
    gpgme_ctx_t ctx;
    gpgme_signature_t sig;
    gpgme_data_t signature_data, signed_data;

    gpgme_error_t error = gpgme_new (&ctx);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        return GPGME_ERROR;
    }

    gpgme_set_armor (ctx, 1);

    error = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        gpgme_release (ctx);
        return GPGME_ERROR;
    }

    const char *keyring_dir = gpgme_get_dirinfo ("homedir");
    error = gpgme_ctx_set_engine_info (ctx, GPGME_PROTOCOL_OpenPGP, NULL, keyring_dir);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        gpgme_release (ctx);
        return GPGME_ERROR;
    }

    FILE *sig_fp = g_fopen (detached_signature_path, "r");
    if (sig_fp == NULL) {
        g_printerr ("Couldn't open detached signature file\n");
        gpgme_release (ctx);
        return FILE_OPEN_ERROR;
    }

    FILE *sig_data_fp = g_fopen (signed_file_path, "r");
    if (sig_data_fp == NULL) {
        g_printerr ("Couldn't open signed file\n");
        gpgme_release (ctx);
        fclose (sig_fp);
        return FILE_OPEN_ERROR;
    }

    error = gpgme_data_new_from_stream (&signature_data, sig_fp);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        fclose (sig_fp);
        fclose (sig_data_fp);
        gpgme_release (ctx);
        return GPGME_ERROR;
    }

    error = gpgme_data_new_from_stream (&signed_data, sig_data_fp);
    if (error) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        fclose (sig_fp);
        fclose (sig_data_fp);
        gpgme_release (ctx);
        gpgme_data_release (signature_data);
        return GPGME_ERROR;
    }

    error = gpgme_op_verify (ctx, signature_data, signed_data, NULL);

    gpgme_data_release (signature_data);
    gpgme_data_release (signed_data);

    fclose (sig_fp);
    fclose (sig_data_fp);

    if (error != GPG_ERR_NO_ERROR) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        gpgme_release (ctx);
        return GPGME_ERROR;
    }

    gpgme_verify_result_t result = gpgme_op_verify_result (ctx);
    if (!result) {
        g_printerr ("%s: %s\n", gpgme_strsource (error), gpgme_strerror (error));
        gpgme_release (ctx);
        return GPGME_ERROR;
    }

    sig = result->signatures;
    if (!sig) {
        gpgme_release (ctx);
        return NO_GPG_KEYS_AVAILABLE;
    }

    for (; sig; sig = sig->next) {
        if ((sig->summary & GPGME_SIGSUM_VALID) || (sig->summary & GPGME_SIGSUM_GREEN)) {
            gpgme_release (ctx);
            return SIGNATURE_OK;
        } else if (sig->summary == 0 && sig->status == GPG_ERR_NO_ERROR) {  // Valid but key is not certified with a trusted signature
            gpgme_release (ctx);
            return SIGNATURE_OK_KEY_NOT_TRUSTED;
        }
    }

    gpgme_release (ctx);
    return BAD_SIGNATURE;
}


static void
init_gpgme ()
{
    setlocale (LC_ALL, "");
    gpgme_check_version (NULL);
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef LC_MESSAGES
    gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif
}


static void
cleanup (FILE               *f1,
         GFile              *f2,
         GFileOutputStream  *ostream,
         gchar              *buf,
         gpgme_key_t        *sk,
         gpgme_ctx_t        *ctx)
{
    if (f1 != NULL) {
        fclose (f1);
    }

    if (f2 != NULL) {
        g_object_unref (f2);
    }

    if (ostream != NULL) {
        g_output_stream_close (G_OUTPUT_STREAM (ostream), NULL, NULL);
        g_object_unref (ostream);
    }

    g_free (buf);

    if (sk != NULL) {
        gpgme_key_release (*sk);
    }

    if (ctx != NULL) {
        gpgme_release (*ctx);
    }

}
