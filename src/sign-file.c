#include <gtk/gtk.h>
#include <gpgme.h>
#include <locale.h>
#include <glib/gstdio.h>

#define MAXLEN 4096

static void init_gpgme (void);


void
sign_file (const gchar *input_file_path, const gchar *fpr)
{

    gpgme_error_t error;
    gpgme_ctx_t context;
    gpgme_key_t signing_key;
    gpgme_data_t clear_text, signed_text;
    gpgme_sign_result_t result;
    gpgme_user_id_t user;
    gchar *buffer;
    gssize nbytes;

    init_gpgme ();

    error = gpgme_new (&context);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        return;
    }

    gpgme_set_armor (context, 0);

    error = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        return;
    }

    const char *keyring_dir = gpgme_get_dirinfo ("homedir");
    error = gpgme_ctx_set_engine_info (context, GPGME_PROTOCOL_OpenPGP, NULL, keyring_dir);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        return;
    }

    error = gpgme_get_key (context, fpr, &signing_key, 1);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        return;
    }

    error = gpgme_signers_add (context, signing_key);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        return;
    }

    FILE *infp = g_fopen (input_file_path, "r");
    if (infp == NULL) {
        g_printerr ("Couldn't open input file\n");
        return;
    }

    error = gpgme_data_new_from_stream(&clear_text, infp);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        fclose (infp);
        return;
    }

    error = gpgme_data_new(&signed_text);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        fclose (infp);
        return;
    }

    error = gpgme_op_sign (context, clear_text, signed_text, GPGME_SIG_MODE_DETACH);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        fclose (infp);
        return;
    }

    result = gpgme_op_sign_result (context);
    if (result->invalid_signers) {
        g_printerr ("Invalid signer found: %s\n", result->invalid_signers->fpr);
        fclose (infp);
        return;
    }
    if (!result->signatures || result->signatures->next) {
        g_printerr ("Unexpected number of signatures created\n");
        fclose (infp);
        return;
    }

    error = gpgme_data_seek (signed_text, 0, SEEK_SET);
    if (error) {
        g_printerr ("%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource (error), gpgme_strerror (error));
        fclose (infp);
        return;
    }

    buffer = g_try_malloc0 (MAXLEN);
    if (buffer == NULL) {
        g_printerr ("Couldn't allocate memory\n");
        fclose (infp);
        return;
    }

    nbytes = gpgme_data_read (signed_text, buffer, MAXLEN);
    if (nbytes == -1) {
        g_printerr ("Error while reading data\n");
        fclose (infp);
        return;
    }

    gchar *output_file_path = g_strconcat (input_file_path, ".sig", NULL);
    FILE *fpout = g_fopen (output_file_path, "w");
    if (fpout == NULL) {
        g_printerr ("Couldn't open output file for writing\n");
        fclose (infp);
        g_free (output_file_path);
        return;
    }
    fwrite (buffer, nbytes, 1, fpout);

    fclose (infp);
    fclose (fpout);

    g_free (output_file_path);
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