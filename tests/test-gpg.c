#include <glib.h>
#include <glib/gstdio.h>

#include "gpgme-misc.h"

static void
run_gpg (const gchar *gpg_path, gchar **arguments)
{
    gchar *stdout_data = NULL;
    gchar *stderr_data = NULL;
    gint status = 0;
    GError *error = NULL;
    g_assert_true (g_spawn_sync (
        NULL, arguments, NULL, G_SPAWN_DEFAULT, NULL, NULL,
        &stdout_data, &stderr_data, &status, &error));
    g_assert_no_error (error);
    if (!g_spawn_check_wait_status (status, &error)) {
        g_test_message ("%s failed: %s\n%s", gpg_path,
                        error->message, stderr_data);
        g_assert_no_error (error);
    }
    g_free (stdout_data);
    g_free (stderr_data);
}

int
main (int argc, char **argv)
{
    g_test_init (&argc, &argv, NULL);
    g_assert_cmpint (argc, >=, 2);
    const gchar *gpg_path = argv[1];

    GError *error = NULL;
    g_autofree gchar *home = g_dir_make_tmp ("gtkcrypto-gpg-XXXXXX",
                                             &error);
    g_assert_no_error (error);
    g_assert_cmpint (g_chmod (home, 0700), ==, 0);
    g_setenv ("GNUPGHOME", home, TRUE);

    g_autofree gchar *gpgconf = g_find_program_in_path ("gpgconf");
    g_assert_nonnull (gpgconf);
    gchar *launch_args[] = {
        gpgconf, (gchar *)"--launch", (gchar *)"gpg-agent", NULL
    };
    run_gpg (gpgconf, launch_args);

    g_autofree gchar *gpg_connect_agent =
        g_find_program_in_path ("gpg-connect-agent");
    if (gpg_connect_agent == NULL) {
        g_test_skip ("gpg-connect-agent is unavailable");
        return 77;
    }

    gchar *agent_args[] = {
        gpg_connect_agent, (gchar *)"/bye", NULL
    };
    gchar *agent_stdout = NULL;
    gchar *agent_stderr = NULL;
    gint agent_status = 0;
    gboolean agent_spawned = g_spawn_sync (
        NULL, agent_args, NULL, G_SPAWN_DEFAULT, NULL, NULL,
        &agent_stdout, &agent_stderr, &agent_status, &error);
    gboolean agent_ready =
        agent_spawned && g_spawn_check_wait_status (agent_status, NULL);
    if (!agent_ready) {
        g_test_message ("gpg-agent unavailable: %s",
                        agent_stderr != NULL ? agent_stderr :
                        (error != NULL ? error->message : "unknown error"));
        g_clear_error (&error);
        g_free (agent_stdout);
        g_free (agent_stderr);
        g_test_skip ("gpg-agent cannot be used in this environment");
        return 77;
    }
    g_free (agent_stdout);
    g_free (agent_stderr);

    gchar *generate_args[] = {
        (gchar *)gpg_path,
        (gchar *)"--batch",
        (gchar *)"--pinentry-mode", (gchar *)"loopback",
        (gchar *)"--passphrase", (gchar *)"",
        (gchar *)"--quick-generate-key",
        (gchar *)"GTKCrypto Test <gtkcrypto@example.invalid>",
        (gchar *)"default", (gchar *)"default", (gchar *)"1d",
        NULL
    };
    run_gpg (gpg_path, generate_args);

    GSList *keys = get_available_keys ();
    g_assert_nonnull (keys);
    g_assert_true (keys != GPGME_ERROR);
    KeyInfo *key = keys->data;
    g_assert_nonnull (key);
    g_assert_nonnull (key->key_fpr);

    g_autofree gchar *payload = g_build_filename (home, "payload", NULL);
    const gchar original[] = "signed payload\n";
    g_assert_true (g_file_set_contents (payload, original, -1, &error));
    g_assert_no_error (error);

    g_assert_true (sign_file (payload, key->key_fpr) == SIGN_OK);
    g_autofree gchar *signature = g_strconcat (payload, ".sig", NULL);
    g_assert_true (g_file_test (signature, G_FILE_TEST_IS_REGULAR));
    gpointer verify = verify_signature (payload, signature);
    g_assert_true (verify == SIGNATURE_OK ||
                   verify == SIGNATURE_OK_KEY_NOT_TRUSTED);

    g_assert_true (g_file_set_contents (payload, "tampered\n", -1, &error));
    g_assert_no_error (error);
    g_assert_true (verify_signature (payload, signature) == BAD_SIGNATURE);

    g_slist_free_full (keys, (GDestroyNotify)key_info_free);
    return 0;
}
