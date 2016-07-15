#include <gtk/gtk.h>
#include <gpgme.h>
#include <locale.h>
#include <glib/gstdio.h>
#include "gpgme-misc.h"


static void init_gpgme (void);

static void cleanup (FILE *f1, FILE *f2, gchar *buf, gpgme_key_t *signing_key, gpgme_ctx_t *context);


gpointer
sign_file (const gchar *input_file_path, const gchar *fpr)
{
    gpgme_error_t error;
    gpgme_ctx_t context;
    gpgme_key_t signing_key;
    gpgme_data_t clear_text, signed_text;
    gpgme_sign_result_t result;
    gchar *buffer;
    gssize nbytes;

    error = gpgme_new (&context);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        return GPGME_ERROR;
    }

    gpgme_set_armor (context, 0);

    error = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        gpgme_release (context);
        return GPGME_ERROR;
    }

    const char *keyring_dir = gpgme_get_dirinfo ("homedir");
    error = gpgme_ctx_set_engine_info (context, GPGME_PROTOCOL_OpenPGP, NULL, keyring_dir);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        gpgme_release (context);
        return GPGME_ERROR;
    }

    error = gpgme_get_key (context, fpr, &signing_key, 1);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        gpgme_release (context);
        return GPGME_ERROR;
    }

    error = gpgme_signers_add (context, signing_key);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        cleanup (NULL, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    FILE *infp = g_fopen (input_file_path, "r");
    if (infp == NULL) {
        g_printerr ("Couldn't open input file\n");
        cleanup (NULL, NULL, NULL, &signing_key, &context);
        return FILE_OPEN_ERROR;
    }

    error = gpgme_data_new_from_stream(&clear_text, infp);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        cleanup (infp, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    error = gpgme_data_new(&signed_text);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        cleanup (infp, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    error = gpgme_op_sign (context, clear_text, signed_text, GPGME_SIG_MODE_DETACH);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        cleanup (infp, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    result = gpgme_op_sign_result (context);
    if (result->invalid_signers) {
        g_printerr ("Invalid signer found: %s\n", result->invalid_signers->fpr);
        cleanup (infp, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }
    if (!result->signatures || result->signatures->next) {
        g_printerr ("Unexpected number of signatures created\n");
        cleanup (infp, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    error = gpgme_data_seek (signed_text, 0, SEEK_SET);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        cleanup (infp, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    buffer = g_try_malloc0 (SIG_MAXLEN);
    if (buffer == NULL) {
        g_printerr ("Couldn't allocate memory\n");
        cleanup (infp, NULL, NULL, &signing_key, &context);
        return MEMORY_ALLOCATION_ERROR;
    }

    nbytes = gpgme_data_read (signed_text, buffer, SIG_MAXLEN);
    if (nbytes == -1) {
        g_printerr ("Error while reading data\n");
        cleanup (infp, NULL, NULL, &signing_key, &context);
        return GPGME_ERROR;
    }

    gchar *output_file_path = g_strconcat (input_file_path, ".sig", NULL);
    FILE *fpout = g_fopen (output_file_path, "w");
    if (fpout == NULL) {
        g_printerr ("Couldn't open output file for writing\n");
        cleanup (infp, NULL, output_file_path, &signing_key, &context);
        return FILE_OPEN_ERROR;
    }
    gssize wbytes = fwrite (buffer, nbytes, 1, fpout);
    if (wbytes != nbytes) {
        g_printerr ("Couldn't write the request number of bytes\n");
        cleanup (infp, fpout, output_file_path, &signing_key, &context);
        return FILE_WRITE_ERROR;
    }

    cleanup (infp, fpout, output_file_path, &signing_key, &context);

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
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (err), gpgme_strerror (err));
        return GPGME_ERROR;
    }

    err = gpgme_op_keylist_start (ctx, NULL, 1);
    if (err) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (err), gpgme_strerror (err));
        gpgme_release (ctx);
        return GPGME_ERROR;
    }

    GSList *list = NULL;
    KeyInfo *key_info;

    while (1) {
        err = gpgme_op_keylist_next (ctx, &key);
        if (err) {
            break;
        }
        key_info = g_new0 (KeyInfo, 1);
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

        list = g_slist_append (list, g_memdup (list, sizeof (KeyInfo)));

        g_free (key_info);

        gpgme_key_release (key);
    }

    gpgme_release (ctx);

    return list;
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
cleanup (FILE *f1, FILE *f2, gchar *buf, gpgme_key_t *sk, gpgme_ctx_t *ctx)
{
    if (f1 != NULL) {
        fclose (f1);
    }

    if (f2 != NULL) {
        fclose (f2);
    }

    if (buf != NULL) {
        g_free (buf);
    }

    if (sk != NULL) {
        gpgme_key_release (*sk);
    }

    if (ctx != NULL) {
        gpgme_release (*ctx);
    }

}