#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>

#include "../hash.h"
#include "../gtkcrypto.h"
#include "../encrypt-files-cb.h"
#include "../decrypt-files-cb.h"

#define GCRYPT_MIN_VER  "1.10.1"
#define SECMEM_SIZE     32768
#define MIN_PWD_LEN     8

#define EXIT_USAGE 2
#define EXIT_AUTHENTICATION 3
#define EXIT_EXISTS 4
#define EXIT_INTERRUPTED 130

static int
exit_code_for_error (const GError *error)
{
    if (error != NULL && error->domain == GTKCRYPTO_ERROR) {
        if (error->code == GTKCRYPTO_ERROR_AUTHENTICATION) {
            return EXIT_AUTHENTICATION;
        }
        if (error->code == GTKCRYPTO_ERROR_EXISTS) {
            return EXIT_EXISTS;
        }
        if (error->code == GTKCRYPTO_ERROR_CANCELLED) {
            return EXIT_INTERRUPTED;
        }
    }
    return 1;
}

typedef struct {
    const gchar *cli_name;
    gint         gcry_id;
    gint         digest_size;
} HashName;

static const HashName HASH_NAMES[] = {
    { "md5",          GCRY_MD_MD5,          MD5_DIGEST_SIZE         },
    { "sha1",         GCRY_MD_SHA1,         SHA1_DIGEST_SIZE        },
    { "sha256",       GCRY_MD_SHA256,       SHA256_DIGEST_SIZE      },
    { "sha384",       GCRY_MD_SHA384,       SHA384_DIGEST_SIZE      },
    { "sha512",       GCRY_MD_SHA512,       SHA512_DIGEST_SIZE      },
    { "sha3-256",     GCRY_MD_SHA3_256,     SHA3_256_DIGEST_SIZE    },
    { "sha3-384",     GCRY_MD_SHA3_384,     SHA3_384_DIGEST_SIZE    },
    { "sha3-512",     GCRY_MD_SHA3_512,     SHA3_512_DIGEST_SIZE    },
    { "blake2b-256",  GCRY_MD_BLAKE2B_256,  BLAKE2B_256_DIGEST_SIZE },
    { "blake2b-512",  GCRY_MD_BLAKE2B_512,  BLAKE2B_512_DIGEST_SIZE },
    { "gost94",       GCRY_MD_GOSTR3411_94, GOST94_DIGEST_SIZE      },
    { "whirlpool",    GCRY_MD_WHIRLPOOL,    WHIRLPOOL_DIGEST_SIZE   },
};

/* ---- Interruption handling ----
 *
 * While a file operation runs, SIGINT/SIGTERM/SIGHUP are blocked and consumed
 * by a helper thread that cancels the operation. The core then aborts and
 * removes its temporary output file instead of leaving ".name.XXXXXX" behind.
 * It is only active around the core call, so Ctrl-C at the password prompt
 * keeps its default behaviour. */

static GCancellable *cli_cancellable;
static pthread_t     signal_thread;
static sigset_t      signal_set;
static sigset_t      saved_mask;
static gboolean      signal_thread_running;

static void *
signal_thread_main (void *arg)
{
    (void)arg;
    int sig = 0;
    if (sigwait (&signal_set, &sig) == 0 && sig != SIGUSR1) {
        g_cancellable_cancel (cli_cancellable);
    }
    return NULL;
}

static GCancellable *
interrupt_guard_begin (void)
{
    cli_cancellable = g_cancellable_new ();
    sigemptyset (&signal_set);
    sigaddset (&signal_set, SIGINT);
    sigaddset (&signal_set, SIGTERM);
    sigaddset (&signal_set, SIGHUP);
    sigaddset (&signal_set, SIGUSR1);
    pthread_sigmask (SIG_BLOCK, &signal_set, &saved_mask);
    signal_thread_running =
        pthread_create (&signal_thread, NULL, signal_thread_main, NULL) == 0;
    if (!signal_thread_running) {
        pthread_sigmask (SIG_SETMASK, &saved_mask, NULL);
    }
    return cli_cancellable;
}

static void
interrupt_guard_end (void)
{
    if (signal_thread_running) {
        pthread_kill (signal_thread, SIGUSR1);
        pthread_join (signal_thread, NULL);
        pthread_sigmask (SIG_SETMASK, &saved_mask, NULL);
        signal_thread_running = FALSE;
    }
    g_clear_object (&cli_cancellable);
}


/* ---- Init ---- */

static int
init_gcrypt (void)
{
    if (!gcry_check_version (GCRYPT_MIN_VER)) {
        fprintf (stderr, "libgcrypt %s or newer is required\n", GCRYPT_MIN_VER);
        return -1;
    }
    if (gcry_control (GCRYCTL_INIT_SECMEM, SECMEM_SIZE, 0)) {
        fprintf (stderr, "couldn't init libgcrypt secure memory\n");
        return -1;
    }
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    return 0;
}


/* ---- Lookups ---- */

static const HashName *
lookup_hash (const gchar *name)
{
    for (gsize i = 0; i < G_N_ELEMENTS (HASH_NAMES); i++) {
        if (g_ascii_strcasecmp (name, HASH_NAMES[i].cli_name) == 0) {
            return &HASH_NAMES[i];
        }
    }
    return NULL;
}

static gchar *
join_names (const HashName *names, gsize n)
{
    GString *s = g_string_new (NULL);
    for (gsize i = 0; i < n; i++) {
        if (i > 0) g_string_append (s, ", ");
        g_string_append (s, names[i].cli_name);
    }
    return g_string_free (s, FALSE);
}

/* ---- Password helpers ---- */

static void
secure_wipe (char *p, gsize len)
{
    if (p == NULL) return;
#if defined(__GLIBC__)
    explicit_bzero (p, len);
#else
    volatile char *vp = (volatile char *)p;
    while (len--) *vp++ = 0;
#endif
}

static gchar *
to_secure (const gchar *src)
{
    gsize need = strlen (src) + 1;
    gchar *secure = gcry_malloc_secure (need);
    if (secure == NULL) return NULL;
    memcpy (secure, src, need);
    return secure;
}

static gchar *
read_password_file (const gchar *path, GError **err)
{
    struct stat st;
    if (g_lstat (path, &st) != 0) {
        g_set_error (err, G_FILE_ERROR, g_file_error_from_errno (errno),
                     "Unable to inspect password file: %s",
                     g_strerror (errno));
        return NULL;
    }
    if (!S_ISREG (st.st_mode) || S_ISLNK (st.st_mode)) {
        g_set_error_literal (err, G_FILE_ERROR, G_FILE_ERROR_INVAL,
                             "Password file must be a regular file, not a symlink");
        return NULL;
    }
    if ((st.st_mode & 0077) != 0) {
        g_set_error_literal (err, G_FILE_ERROR, G_FILE_ERROR_ACCES,
                             "Password file must not be accessible by group or others");
        return NULL;
    }

    gchar *contents = NULL;
    gsize len = 0;
    if (!g_file_get_contents (path, &contents, &len, err)) return NULL;

    /* Take only the first line; strip trailing CR/LF. */
    gchar *nl = strchr (contents, '\n');
    if (nl) *nl = '\0';
    g_strchomp (contents);

    gchar *secure = to_secure (contents);
    secure_wipe (contents, len);
    g_free (contents);
    return secure;
}

static gchar *
prompt_password_once (const gchar *prompt)
{
    gchar *p = getpass (prompt);
    if (p == NULL) return NULL;
    gchar *secure = to_secure (p);
    secure_wipe (p, strlen (p));
    return secure;
}

static gchar *
prompt_password_confirm (void)
{
    gchar *first = prompt_password_once ("Password: ");
    if (first == NULL) return NULL;

    gchar *p2 = getpass ("Confirm password: ");
    if (p2 == NULL) {
        gcry_free (first);
        return NULL;
    }
    gboolean match = strcmp (first, p2) == 0;
    secure_wipe (p2, strlen (p2));

    if (!match) {
        fprintf (stderr, "Passwords do not match.\n");
        gcry_free (first);
        return NULL;
    }
    return first;
}

/* Returns gcry-secure-allocated password, or NULL on error (already reported). */
static gchar *
obtain_password (const gchar *password_file, gboolean confirm)
{
    gchar *pwd = NULL;
    if (password_file != NULL) {
        GError *err = NULL;
        pwd = read_password_file (password_file, &err);
        if (pwd == NULL) {
            fprintf (stderr, "Failed to read password file: %s\n",
                     err ? err->message : "unknown error");
            g_clear_error (&err);
            return NULL;
        }
    } else {
        pwd = confirm ? prompt_password_confirm () : prompt_password_once ("Password: ");
        if (pwd == NULL) return NULL;
    }

    /* The minimum only applies to new passwords: older files may have been
     * encrypted with shorter ones and must stay readable. */
    if (confirm && strlen (pwd) < MIN_PWD_LEN) {
        fprintf (stderr, "Password must be at least %d characters.\n", MIN_PWD_LEN);
        gcry_free (pwd);
        return NULL;
    }
    if (*pwd == '\0') {
        fprintf (stderr, "Password must not be empty.\n");
        gcry_free (pwd);
        return NULL;
    }
    return pwd;
}


/* ---- Subcommand: hash ---- */

static int
cmd_hash (int argc, char **argv)
{
    g_autofree gchar *algo_arg = NULL;
    g_auto(GStrv) files = NULL;

    GOptionEntry entries[] = {
        { "algo", 'a', 0, G_OPTION_ARG_STRING, &algo_arg,
          "Algorithm name(s), comma-separated. Default: sha256.", "NAME[,NAME...]" },
        { G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &files,
          NULL, NULL },
        { 0 },
    };

    g_autoptr(GOptionContext) ctx = g_option_context_new ("FILE");
    g_autofree gchar *valid = join_names (HASH_NAMES, G_N_ELEMENTS (HASH_NAMES));
    g_autofree gchar *summary = g_strdup_printf (
        "Compute one or more hash digests of FILE.\n\n"
        "Output format matches sha256sum: '<hex>  FILE' per line.\n\n"
        "Available algorithms: %s.", valid);
    g_option_context_set_summary (ctx, summary);
    g_option_context_add_main_entries (ctx, entries, NULL);

    GError *err = NULL;
    if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
        fprintf (stderr, "%s\n", err->message);
        g_error_free (err);
        return EXIT_USAGE;
    }
    if (files == NULL || files[0] == NULL || files[1] != NULL) {
        fprintf (stderr, "Expected exactly one FILE argument.\n");
        return EXIT_USAGE;
    }
    const gchar *path = files[0];

    g_auto(GStrv) algos = g_strsplit (algo_arg ? algo_arg : "sha256", ",", -1);
    gint ids[G_N_ELEMENTS (HASH_NAMES)];
    gint sizes[G_N_ELEMENTS (HASH_NAMES)];
    guint n = 0;
    for (gsize i = 0; algos[i] != NULL; i++) {
        const gchar *name = g_strstrip (algos[i]);
        if (*name == '\0') continue;
        const HashName *hn = lookup_hash (name);
        if (hn == NULL) {
            fprintf (stderr, "Unknown algorithm: %s\nValid: %s\n", name, valid);
            return EXIT_USAGE;
        }
        if (n >= G_N_ELEMENTS (HASH_NAMES)) {
            fprintf (stderr, "Too many algorithms requested.\n");
            return EXIT_USAGE;
        }
        ids[n] = hn->gcry_id;
        sizes[n] = hn->digest_size;
        n++;
    }
    if (n == 0) {
        fprintf (stderr, "No algorithm given.\n");
        return EXIT_USAGE;
    }

    /* One read pass over the file feeds every requested digest. */
    gchar *hex[G_N_ELEMENTS (HASH_NAMES)];
    GCancellable *cancellable = interrupt_guard_begin ();
    g_autoptr(GError) hash_error = NULL;
    gboolean ok = gtkcrypto_hash_file (path, ids, sizes, n, cancellable,
                                       hex, &hash_error);
    interrupt_guard_end ();
    if (!ok) {
        fprintf (stderr, "%s\n", hash_error->message);
        return exit_code_for_error (hash_error);
    }
    for (guint i = 0; i < n; i++) {
        printf ("%s  %s\n", hex[i], path);
        g_free (hex[i]);
    }
    return 0;
}


/* ---- Subcommand: encrypt ---- */

static int
cmd_encrypt (int argc, char **argv)
{
    g_autofree gchar *pwd_file = NULL;
    g_autofree gchar *output_arg = NULL;
    gboolean force = FALSE;
    g_auto(GStrv) files = NULL;

    GOptionEntry entries[] = {
        { "password-file", 'p', 0, G_OPTION_ARG_FILENAME, &pwd_file,
          "Read password from PATH (first line). Otherwise prompt interactively.", "PATH" },
        { "output", 'o', 0, G_OPTION_ARG_FILENAME, &output_arg,
          "Write encrypted data to PATH. Default: FILE.enc.", "PATH" },
        { "force", 'f', 0, G_OPTION_ARG_NONE, &force,
          "Replace an existing output atomically.", NULL },
        { G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &files, NULL, NULL },
        { 0 },
    };

    g_autoptr(GOptionContext) ctx = g_option_context_new ("FILE");
    g_option_context_set_summary (ctx,
        "Encrypt FILE using the portable GTC3 format (AES-256-GCM + Argon2id).\n"
        "The result is written to FILE.enc unless --output is supplied.\n"
        "The password is asked interactively (and confirmed) unless --password-file is given.");
    g_option_context_add_main_entries (ctx, entries, NULL);

    GError *err = NULL;
    if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
        fprintf (stderr, "%s\n", err->message);
        g_error_free (err);
        return EXIT_USAGE;
    }
    if (files == NULL || files[0] == NULL || files[1] != NULL) {
        fprintf (stderr, "Expected exactly one FILE argument.\n");
        return EXIT_USAGE;
    }

    gchar *pwd = obtain_password (pwd_file, TRUE);
    if (pwd == NULL) return 1;

    g_autofree gchar *default_output = output_arg == NULL ?
        g_strconcat (files[0], ".enc", NULL) : NULL;
    const gchar *output = output_arg != NULL ? output_arg : default_output;
    GError *crypto_error = NULL;
    GCancellable *cancellable = interrupt_guard_begin ();
    gboolean ok = gtkcrypto_encrypt_file (files[0], output,
                                          (const guint8 *)pwd, strlen (pwd),
                                          force, cancellable, &crypto_error);
    interrupt_guard_end ();
    secure_wipe (pwd, strlen (pwd));
    gcry_free (pwd);

    if (!ok) {
        int rc = exit_code_for_error (crypto_error);
        fprintf (stderr, "%s\n", crypto_error->message);
        g_error_free (crypto_error);
        return rc;
    }
    return 0;
}


/* ---- Subcommand: decrypt ---- */

static int
cmd_decrypt (int argc, char **argv)
{
    g_autofree gchar *pwd_file = NULL;
    g_autofree gchar *output_arg = NULL;
    gboolean delete_after = FALSE;
    gboolean force = FALSE;
    g_auto(GStrv) files = NULL;

    GOptionEntry entries[] = {
        { "password-file", 'p', 0, G_OPTION_ARG_FILENAME, &pwd_file,
          "Read password from PATH (first line). Otherwise prompt interactively.", "PATH" },
        { "delete", 'd', 0, G_OPTION_ARG_NONE, &delete_after,
          "Delete the encrypted FILE after a successful decryption.", NULL },
        { "output", 'o', 0, G_OPTION_ARG_FILENAME, &output_arg,
          "Write plaintext to PATH.", "PATH" },
        { "force", 'f', 0, G_OPTION_ARG_NONE, &force,
          "Replace an existing output atomically.", NULL },
        { G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &files, NULL, NULL },
        { 0 },
    };

    g_autoptr(GOptionContext) ctx = g_option_context_new ("FILE");
    g_option_context_set_summary (ctx,
        "Decrypt FILE. The output is written next to the source: '.enc' is stripped\n"
        "from the name when present, otherwise '.decrypted' is appended.");
    g_option_context_add_main_entries (ctx, entries, NULL);

    GError *err = NULL;
    if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
        fprintf (stderr, "%s\n", err->message);
        g_error_free (err);
        return EXIT_USAGE;
    }
    if (files == NULL || files[0] == NULL || files[1] != NULL) {
        fprintf (stderr, "Expected exactly one FILE argument.\n");
        return EXIT_USAGE;
    }

    gchar *pwd = obtain_password (pwd_file, FALSE);
    if (pwd == NULL) return 1;

    g_autofree gchar *default_output = NULL;
    if (output_arg == NULL) {
        default_output = g_str_has_suffix (files[0], ".enc") ?
            g_strndup (files[0], strlen (files[0]) - 4) :
            g_strconcat (files[0], ".decrypted", NULL);
    }
    const gchar *output = output_arg != NULL ? output_arg : default_output;
    GError *crypto_error = NULL;
    GCancellable *cancellable = interrupt_guard_begin ();
    gboolean ok = gtkcrypto_decrypt_file (files[0], output,
                                          (const guint8 *)pwd, strlen (pwd),
                                          force, cancellable, &crypto_error);
    interrupt_guard_end ();
    secure_wipe (pwd, strlen (pwd));
    gcry_free (pwd);

    if (!ok) {
        int rc = exit_code_for_error (crypto_error);
        fprintf (stderr, "%s\n", crypto_error->message);
        g_error_free (crypto_error);
        return rc;
    }

    if (delete_after) {
        if (g_unlink (files[0]) != 0) {
            fprintf (stderr, "Decryption succeeded but failed to delete %s\n", files[0]);
            return 1;
        }
    }
    return 0;
}


/* ---- Top-level dispatch ---- */

static void
print_top_help (FILE *out)
{
    fprintf (out,
        "Usage: gtkcrypto-cli SUBCOMMAND [OPTIONS] FILE\n"
        "\n"
        "Subcommands:\n"
        "  hash      Compute one or more hash digests of FILE\n"
        "  encrypt   Encrypt FILE to FILE.enc\n"
        "  decrypt   Decrypt FILE\n"
        "\n"
        "Other options:\n"
        "  -h, --help        Show this help and exit\n"
        "      --version     Print version and exit\n"
        "\n"
        "Run 'gtkcrypto-cli SUBCOMMAND --help' for subcommand-specific options.\n");
}

int
main (int argc, char **argv)
{
    if (init_gcrypt () != 0) return 1;

    if (argc < 2) {
        print_top_help (stderr);
        return EXIT_USAGE;
    }

    const gchar *sub = argv[1];

    if (g_strcmp0 (sub, "hash") == 0)    return cmd_hash    (argc - 1, argv + 1);
    if (g_strcmp0 (sub, "encrypt") == 0) return cmd_encrypt (argc - 1, argv + 1);
    if (g_strcmp0 (sub, "decrypt") == 0) return cmd_decrypt (argc - 1, argv + 1);

    if (g_strcmp0 (sub, "--version") == 0) {
        puts (GTKCRYPTO_VERSION);
        return 0;
    }
    if (g_strcmp0 (sub, "--help") == 0 || g_strcmp0 (sub, "-h") == 0) {
        print_top_help (stdout);
        return 0;
    }

    fprintf (stderr, "Unknown subcommand: %s\n\n", sub);
    print_top_help (stderr);
    return EXIT_USAGE;
}
