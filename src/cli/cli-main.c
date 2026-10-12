#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>

#include "../hash.h"
#include "../gtkcrypto.h"
#include "../crypt-common.h"
#include "../encrypt-files-cb.h"
#include "../decrypt-files-cb.h"

#define GCRYPT_MIN_VER  "1.10.1"
#define SECMEM_SIZE     32768
#define MIN_PWD_LEN     8
#define MAX_PWD_LEN     1023

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
 * It is only active around the core calls, so Ctrl-C at the password prompt
 * keeps working. */

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

/* Reads the first line from FD (a pipe, here-string, ...) without ever
 * keeping it in non-secure memory beyond a wiped stack buffer. */
static gchar *
read_password_fd (gint fd, GError **err)
{
    char buf[MAX_PWD_LEN + 1];
    gsize len = 0;
    gboolean too_long = FALSE;

    for (;;) {
        char c;
        ssize_t n = read (fd, &c, 1);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            g_set_error (err, G_FILE_ERROR, g_file_error_from_errno (errno),
                         "Unable to read password: %s", g_strerror (errno));
            secure_wipe (buf, sizeof buf);
            return NULL;
        }
        if (n == 0 || c == '\n') break;
        if (len < MAX_PWD_LEN) {
            buf[len++] = c;
        } else {
            too_long = TRUE;
        }
    }
    buf[len] = '\0';
    if (len > 0 && buf[len - 1] == '\r') buf[--len] = '\0';

    gchar *secure = NULL;
    if (too_long) {
        g_set_error (err, G_FILE_ERROR, G_FILE_ERROR_INVAL,
                     "Password is longer than %d bytes", MAX_PWD_LEN);
    } else {
        secure = to_secure (buf);
    }
    secure_wipe (buf, sizeof buf);
    return secure;
}

/* Best-effort terminal output: a failing prompt write must not abort. */
static void
tty_write (int fd, const char *text)
{
    if (write (fd, text, strlen (text)) < 0) {
        /* nothing sensible to do */
    }
}

static volatile sig_atomic_t prompt_signal;

static void
prompt_signal_handler (int sig)
{
    prompt_signal = sig;
}

/* Reads a password from the controlling terminal with echo disabled. Returns
 * a secure-memory copy, or NULL (with *interrupted set when a signal arrived,
 * after the terminal has been restored). */
static gchar *
prompt_password_once (const gchar *prompt, gboolean *interrupted)
{
    int tty = open ("/dev/tty", O_RDWR | O_CLOEXEC | O_NOCTTY);
    if (tty < 0) {
        fprintf (stderr, "No terminal available: use --password-file or "
                         "--password-fd\n");
        return NULL;
    }

    struct termios old, quiet;
    if (tcgetattr (tty, &old) != 0) {
        fprintf (stderr, "Unable to configure the terminal: %s\n", g_strerror (errno));
        close (tty);
        return NULL;
    }
    quiet = old;
    quiet.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);

    struct sigaction sa, old_int, old_term, old_hup;
    memset (&sa, 0, sizeof sa);
    sa.sa_handler = prompt_signal_handler;
    sigemptyset (&sa.sa_mask);                /* no SA_RESTART: read() returns */
    prompt_signal = 0;
    sigaction (SIGINT, &sa, &old_int);
    sigaction (SIGTERM, &sa, &old_term);
    sigaction (SIGHUP, &sa, &old_hup);

    tcsetattr (tty, TCSAFLUSH, &quiet);
    tty_write (tty, prompt);

    char buf[MAX_PWD_LEN + 1];
    gsize len = 0;
    gboolean too_long = FALSE, failed = FALSE;
    for (;;) {
        char c;
        ssize_t n = read (tty, &c, 1);
        if (prompt_signal != 0) { failed = TRUE; break; }
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { failed = (len == 0 && n < 0); break; }
        if (c == '\n' || c == '\r') break;
        if (len < MAX_PWD_LEN) buf[len++] = c; else too_long = TRUE;
    }
    buf[len] = '\0';

    tcsetattr (tty, TCSAFLUSH, &old);
    tty_write (tty, "\n");
    sigaction (SIGINT, &old_int, NULL);
    sigaction (SIGTERM, &old_term, NULL);
    sigaction (SIGHUP, &old_hup, NULL);
    close (tty);

    if (prompt_signal != 0) {
        *interrupted = TRUE;
        secure_wipe (buf, sizeof buf);
        return NULL;
    }
    gchar *secure = NULL;
    if (too_long) {
        fprintf (stderr, "Password is longer than %d bytes.\n", MAX_PWD_LEN);
    } else if (!failed) {
        secure = to_secure (buf);
    }
    secure_wipe (buf, sizeof buf);
    return secure;
}

static gchar *
prompt_password_confirm (gboolean *interrupted)
{
    gchar *first = prompt_password_once ("Password: ", interrupted);
    if (first == NULL) return NULL;

    gchar *second = prompt_password_once ("Confirm password: ", interrupted);
    if (second == NULL) {
        gcry_free (first);
        return NULL;
    }
    gboolean match = strcmp (first, second) == 0;
    secure_wipe (second, strlen (second));
    gcry_free (second);

    if (!match) {
        fprintf (stderr, "Passwords do not match.\n");
        gcry_free (first);
        return NULL;
    }
    return first;
}

typedef struct {
    const gchar *file;      /* --password-file */
    gint         fd;        /* --password-fd, -1 when unset */
    gboolean     use_stdin; /* --password-stdin */
} PasswordSource;

/* Returns gcry-secure-allocated password, or NULL on error (already reported).
 * NEW_PASSWORD requests confirmation and enforces the minimum length; existing
 * data may have been protected by a shorter one, so decrypt only needs a
 * non-empty password. */
static gchar *
obtain_password (const PasswordSource *src, gboolean new_password,
                 int *exit_code)
{
    gchar *pwd = NULL;
    GError *err = NULL;
    gboolean interrupted = FALSE;

    if (src->file != NULL) {
        pwd = read_password_file (src->file, &err);
    } else if (src->use_stdin || src->fd >= 0) {
        pwd = read_password_fd (src->use_stdin ? STDIN_FILENO : src->fd, &err);
    } else {
        pwd = new_password ? prompt_password_confirm (&interrupted)
                           : prompt_password_once ("Password: ", &interrupted);
        if (pwd == NULL) {
            *exit_code = interrupted ? EXIT_INTERRUPTED : 1;
            return NULL;
        }
    }
    if (pwd == NULL) {
        fprintf (stderr, "Failed to read password: %s\n",
                 err ? err->message : "out of secure memory");
        g_clear_error (&err);
        *exit_code = 1;
        return NULL;
    }

    if (new_password && strlen (pwd) < MIN_PWD_LEN) {
        fprintf (stderr, "Password must be at least %d characters.\n", MIN_PWD_LEN);
        gcry_free (pwd);
        *exit_code = 1;
        return NULL;
    }
    if (*pwd == '\0') {
        fprintf (stderr, "Password must not be empty.\n");
        gcry_free (pwd);
        *exit_code = 1;
        return NULL;
    }
    return pwd;
}


/* ---- Subcommand: hash ---- */

static gboolean
hash_one (const gchar *path, const gint *ids, const gint *sizes, guint n,
          GCancellable *cancellable, gchar **hex, GError **error)
{
    if (g_strcmp0 (path, "-") == 0) {
        return gtkcrypto_hash_fd (STDIN_FILENO, "stdin", ids, sizes, n,
                                  cancellable, hex, error);
    }
    return gtkcrypto_hash_file (path, ids, sizes, n, cancellable, hex, error);
}

/* Verifies a sha256sum-style list ("<hex>  <name>" or "<hex> *<name>").
 * Returns the number of problems (mismatches, unreadable files, bad lines). */
static guint
check_sums (const gchar *list_path, const HashName *hn, gboolean quiet,
            GCancellable *cancellable)
{
    FILE *f = g_strcmp0 (list_path, "-") == 0 ? stdin : fopen (list_path, "r");
    if (f == NULL) {
        fprintf (stderr, "%s: %s\n", list_path, g_strerror (errno));
        return 1;
    }

    guint problems = 0, bad_format = 0, mismatches = 0, unreadable = 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    gsize hex_len = (gsize)hn->digest_size * 2;

    while ((len = getline (&line, &cap, f)) >= 0) {
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;

        gboolean ok_format = (gsize)len > hex_len + 2 &&
                             line[hex_len] == ' ' &&
                             (line[hex_len + 1] == ' ' || line[hex_len + 1] == '*');
        for (gsize i = 0; ok_format && i < hex_len; i++) {
            if (!g_ascii_isxdigit (line[i])) ok_format = FALSE;
        }
        if (!ok_format) {
            bad_format++;
            problems++;
            continue;
        }

        const gchar *name = line + hex_len + 2;
        gchar *hex[1] = { NULL };
        g_autoptr(GError) error = NULL;
        gint id = hn->gcry_id, size = hn->digest_size;
        if (!hash_one (name, &id, &size, 1, cancellable, hex, &error)) {
            if (g_error_matches (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_CANCELLED)) {
                problems++;
                break;
            }
            printf ("%s: FAILED open or read\n", name);
            unreadable++;
            problems++;
            continue;
        }
        if (g_ascii_strncasecmp (hex[0], line, hex_len) == 0) {
            if (!quiet) printf ("%s: OK\n", name);
        } else {
            printf ("%s: FAILED\n", name);
            mismatches++;
            problems++;
        }
        g_free (hex[0]);
    }
    free (line);
    if (f != stdin) fclose (f);

    if (bad_format > 0) {
        fprintf (stderr, "WARNING: %u line%s improperly formatted\n",
                 bad_format, bad_format == 1 ? " is" : "s are");
    }
    if (unreadable > 0) {
        fprintf (stderr, "WARNING: %u listed file%s could not be read\n",
                 unreadable, unreadable == 1 ? "" : "s");
    }
    if (mismatches > 0) {
        fprintf (stderr, "WARNING: %u computed checksum%s did NOT match\n",
                 mismatches, mismatches == 1 ? "" : "s");
    }
    return problems;
}

static int
cmd_hash (int argc, char **argv)
{
    g_autofree gchar *algo_arg = NULL;
    gboolean check = FALSE, quiet = FALSE;
    g_auto(GStrv) files = NULL;

    GOptionEntry entries[] = {
        { "algo", 'a', 0, G_OPTION_ARG_STRING, &algo_arg,
          "Algorithm name(s), comma-separated. Default: sha256.", "NAME[,NAME...]" },
        { "check", 'c', 0, G_OPTION_ARG_NONE, &check,
          "Read checksum lists from the FILEs and verify them (one algorithm).", NULL },
        { "quiet", 'q', 0, G_OPTION_ARG_NONE, &quiet,
          "With --check, do not print OK lines.", NULL },
        { G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &files,
          NULL, NULL },
        { 0 },
    };

    g_autoptr(GOptionContext) ctx = g_option_context_new ("FILE...");
    g_autofree gchar *valid = join_names (HASH_NAMES, G_N_ELEMENTS (HASH_NAMES));
    g_autofree gchar *summary = g_strdup_printf (
        "Compute one or more hash digests of each FILE ('-' reads standard input).\n\n"
        "Output format matches sha256sum: '<hex>  FILE' per line. With --check the\n"
        "FILEs are such lists and each listed file is verified.\n\n"
        "Available algorithms: %s.", valid);
    g_option_context_set_summary (ctx, summary);
    g_option_context_add_main_entries (ctx, entries, NULL);

    GError *err = NULL;
    if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
        fprintf (stderr, "%s\n", err->message);
        g_error_free (err);
        return EXIT_USAGE;
    }
    if (files == NULL || files[0] == NULL) {
        fprintf (stderr, "Expected at least one FILE argument.\n");
        return EXIT_USAGE;
    }

    g_auto(GStrv) algos = g_strsplit (algo_arg ? algo_arg : "sha256", ",", -1);
    const HashName *selected[G_N_ELEMENTS (HASH_NAMES)];
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
        selected[n] = hn;
        ids[n] = hn->gcry_id;
        sizes[n] = hn->digest_size;
        n++;
    }
    if (n == 0) {
        fprintf (stderr, "No algorithm given.\n");
        return EXIT_USAGE;
    }
    if (check && n != 1) {
        fprintf (stderr, "--check works with exactly one algorithm.\n");
        return EXIT_USAGE;
    }

    GCancellable *cancellable = interrupt_guard_begin ();
    int rc = 0;

    for (gsize f = 0; files[f] != NULL && rc != EXIT_INTERRUPTED; f++) {
        if (check) {
            if (check_sums (files[f], selected[0], quiet, cancellable) > 0 && rc == 0) {
                rc = g_cancellable_is_cancelled (cancellable) ?
                     EXIT_INTERRUPTED : 1;
            }
            continue;
        }

        /* One read pass over the file feeds every requested digest. */
        gchar *hex[G_N_ELEMENTS (HASH_NAMES)];
        g_autoptr(GError) hash_error = NULL;
        if (!hash_one (files[f], ids, sizes, n, cancellable, hex, &hash_error)) {
            fprintf (stderr, "%s\n", hash_error->message);
            int code = exit_code_for_error (hash_error);
            if (rc == 0 || code == EXIT_INTERRUPTED) rc = code;
            continue;
        }
        for (guint i = 0; i < n; i++) {
            printf ("%s  %s\n", hex[i], files[f]);
            g_free (hex[i]);
        }
    }

    interrupt_guard_end ();
    return rc;
}


/* ---- Subcommands: encrypt / decrypt ---- */

typedef struct {
    gboolean encrypt;
    gboolean quiet;
    gboolean verbose;
    gboolean force;
    gboolean delete_source;
} CryptOptions;

static gboolean show_progress;
static const gchar *progress_label;
static gint progress_last = -1;

static void
cli_progress_cb (guint64 done, guint64 total, gpointer user_data)
{
    (void)user_data;
    if (total == 0) return;
    gint pct = (gint)(done * 100 / total);
    if (pct != progress_last) {
        progress_last = pct;
        fprintf (stderr, "\r%s: %3d%%", progress_label, pct);
        fflush (stderr);
    }
}

/* Copies all of STDIN into a fresh private temporary file and returns its
 * path. The container format stores the plaintext length in its header, so a
 * stream has to be spooled to disk first. */
static gchar *
spool_stdin (GCancellable *cancellable, GError **error)
{
    g_autofree gchar *path = g_build_filename (g_get_tmp_dir (),
                                               ".gtkcrypto-stdin-XXXXXX", NULL);
    gint fd = g_mkstemp_full (path, O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                     "Unable to create temporary file: %s", g_strerror (errno));
        return NULL;
    }

    guint8 buf[65536];
    gboolean ok = TRUE;
    for (;;) {
        if (!gtkcrypto_check_cancelled (cancellable, error)) { ok = FALSE; break; }
        ssize_t n = read (STDIN_FILENO, buf, sizeof buf);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                         "Unable to read standard input: %s", g_strerror (errno));
            ok = FALSE;
            break;
        }
        if (!gtkcrypto_write_full (fd, buf, (gsize)n, cancellable, error)) {
            ok = FALSE;
            break;
        }
    }
    secure_wipe ((char *)buf, sizeof buf);
    close (fd);
    if (!ok) {
        g_unlink (path);
        return NULL;
    }
    return g_steal_pointer (&path);
}

static gboolean
copy_file_to_stdout (const gchar *path, GCancellable *cancellable,
                     GError **error)
{
    gint fd = g_open (path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0) {
        g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                     "Unable to read result: %s", g_strerror (errno));
        return FALSE;
    }
    guint8 buf[65536];
    gboolean ok = TRUE;
    for (;;) {
        if (!gtkcrypto_check_cancelled (cancellable, error)) { ok = FALSE; break; }
        ssize_t n = read (fd, buf, sizeof buf);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            g_set_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                         "Unable to read result: %s", g_strerror (errno));
            ok = FALSE;
            break;
        }
        if (!gtkcrypto_write_full (STDOUT_FILENO, buf, (gsize)n, cancellable, error)) {
            ok = FALSE;
            break;
        }
    }
    secure_wipe ((char *)buf, sizeof buf);
    close (fd);
    return ok;
}

static gchar *
default_output_name (const gchar *input, gboolean encrypt)
{
    if (g_strcmp0 (input, "-") == 0) {
        return g_strdup ("-");
    }
    if (encrypt) {
        return g_strconcat (input, ".enc", NULL);
    }
    return g_str_has_suffix (input, ".enc") && strlen (input) > 4 ?
        g_strndup (input, strlen (input) - 4) :
        g_strconcat (input, ".decrypted", NULL);
}

/* Processes one input. Returns 0 or an exit code. */
static int
process_one (const CryptOptions *opt, const gchar *input,
             const gchar *output_arg, const gchar *pwd,
             GCancellable *cancellable)
{
    gboolean from_stdin = g_strcmp0 (input, "-") == 0;
    g_autofree gchar *output = output_arg != NULL ? g_strdup (output_arg)
                                                  : default_output_name (input, opt->encrypt);
    gboolean to_stdout = g_strcmp0 (output, "-") == 0;
    g_autoptr(GError) error = NULL;

    if (to_stdout && opt->encrypt && isatty (STDOUT_FILENO)) {
        fprintf (stderr, "Refusing to write encrypted data to a terminal; "
                         "redirect stdout or use --output.\n");
        return EXIT_USAGE;
    }

    /* All locals the 'failed' label touches are declared before the first
     * goto, so no jump can skip an initialisation. */
    g_autofree gchar *spooled_input = NULL;
    g_autofree gchar *temp_output = NULL;
    const gchar *source = input;
    const gchar *destination = output;
    gboolean overwrite = opt->force;
    gboolean ok = FALSE;
    if (from_stdin) {
        spooled_input = spool_stdin (cancellable, &error);
        if (spooled_input == NULL) goto failed;
        source = spooled_input;
    }

    if (to_stdout) {
        /* The core writes atomically to a path, so stage the result in a
         * private temporary file and stream it afterwards. */
        temp_output = g_build_filename (g_get_tmp_dir (),
                                        ".gtkcrypto-out-XXXXXX", NULL);
        gint fd = g_mkstemp_full (temp_output, O_RDWR | O_CLOEXEC, 0600);
        if (fd < 0) {
            g_set_error (&error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_IO,
                         "Unable to create temporary file: %s", g_strerror (errno));
            goto failed;
        }
        close (fd);
        destination = temp_output;
        overwrite = TRUE;
    }

    if (show_progress) {
        progress_label = from_stdin ? "stdin" : input;
        progress_last = -1;
        gtkcrypto_set_progress (cli_progress_cb, NULL);
    }
    ok = opt->encrypt ?
        gtkcrypto_encrypt_file (source, destination, (const guint8 *)pwd,
                                strlen (pwd), overwrite, cancellable, &error) :
        gtkcrypto_decrypt_file (source, destination, (const guint8 *)pwd,
                                strlen (pwd), overwrite, cancellable, &error);
    if (show_progress) {
        gtkcrypto_set_progress (NULL, NULL);
        fputc ('\n', stderr);
    }
    if (ok && to_stdout) {
        ok = copy_file_to_stdout (temp_output, cancellable, &error);
    }

    if (spooled_input != NULL) g_unlink (spooled_input);
    if (temp_output != NULL) g_unlink (temp_output);
    if (!ok) goto failed;

    if (opt->verbose && !opt->quiet) {
        fprintf (stderr, "%s %s -> %s\n", opt->encrypt ? "Encrypted" : "Decrypted",
                 from_stdin ? "stdin" : input, to_stdout ? "stdout" : output);
    }
    if (opt->delete_source && !from_stdin && g_unlink (input) != 0) {
        fprintf (stderr, "Operation succeeded but failed to delete %s: %s\n",
                 input, g_strerror (errno));
        return 1;
    }
    return 0;

failed:
    if (spooled_input != NULL) g_unlink (spooled_input);
    if (temp_output != NULL) g_unlink (temp_output);
    fprintf (stderr, "%s%s%s\n", from_stdin ? "" : input, from_stdin ? "" : ": ",
             error != NULL ? error->message : "Unknown error");
    return exit_code_for_error (error);
}

static int
cmd_crypt (int argc, char **argv, gboolean encrypt)
{
    CryptOptions opt = { .encrypt = encrypt };
    PasswordSource pwd_src = { .fd = -1 };
    g_autofree gchar *pwd_file = NULL;
    g_autofree gchar *output_arg = NULL;
    g_autofree gchar *kdf_arg = NULL;
    gint pwd_fd = -1;
    g_auto(GStrv) files = NULL;

    GOptionEntry entries[] = {
        { "password-file", 'p', 0, G_OPTION_ARG_FILENAME, &pwd_file,
          "Read the password from PATH (first line).", "PATH" },
        { "password-fd", 0, 0, G_OPTION_ARG_INT, &pwd_fd,
          "Read the password (first line) from file descriptor N.", "N" },
        { "password-stdin", 0, 0, G_OPTION_ARG_NONE, &pwd_src.use_stdin,
          "Read the password (first line) from standard input.", NULL },
        { "output", 'o', 0, G_OPTION_ARG_FILENAME, &output_arg,
          "Write the result to PATH ('-' for standard output). Single input only.", "PATH" },
        { "force", 'f', 0, G_OPTION_ARG_NONE, &opt.force,
          "Replace existing output atomically.", NULL },
        { "delete", 'd', 0, G_OPTION_ARG_NONE, &opt.delete_source,
          encrypt ? "Delete the original FILE after a successful encryption."
                  : "Delete the encrypted FILE after a successful decryption.", NULL },
        { "quiet", 'q', 0, G_OPTION_ARG_NONE, &opt.quiet,
          "Only print errors.", NULL },
        { "verbose", 'v', 0, G_OPTION_ARG_NONE, &opt.verbose,
          "Print a line per processed file and, on a terminal, progress.", NULL },
        { G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &files, NULL, NULL },
        { 0 },
    };
    GOptionEntry kdf_entries[] = {
        { "kdf", 0, 0, G_OPTION_ARG_STRING, &kdf_arg,
          "Key derivation strength: standard (default), strong or maximum.", "LEVEL" },
        { 0 },
    };

    g_autoptr(GOptionContext) ctx = g_option_context_new ("FILE...");
    g_option_context_set_summary (ctx, encrypt ?
        "Encrypt each FILE using the portable GTC3 format (AES-256-GCM + Argon2id).\n"
        "The result is written to FILE.enc unless --output is supplied. FILE '-'\n"
        "reads standard input (the result then goes to standard output).\n"
        "The password is asked interactively (and confirmed) unless one of the\n"
        "--password-* options is given." :
        "Decrypt each FILE. The output is written next to the source: '.enc' is\n"
        "stripped from the name when present, otherwise '.decrypted' is appended.\n"
        "FILE '-' reads standard input (the result then goes to standard output).");
    g_option_context_add_main_entries (ctx, entries, NULL);
    if (encrypt) {
        g_option_context_add_main_entries (ctx, kdf_entries, NULL);
    }

    GError *err = NULL;
    if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
        fprintf (stderr, "%s\n", err->message);
        g_error_free (err);
        return EXIT_USAGE;
    }
    if (files == NULL || files[0] == NULL) {
        fprintf (stderr, "Expected at least one FILE argument.\n");
        return EXIT_USAGE;
    }
    guint n_files = g_strv_length (files);
    if (output_arg != NULL && n_files > 1) {
        fprintf (stderr, "--output can only be used with a single FILE.\n");
        return EXIT_USAGE;
    }
    guint stdin_inputs = 0;
    for (guint i = 0; i < n_files; i++) {
        if (g_strcmp0 (files[i], "-") == 0) stdin_inputs++;
    }
    if (stdin_inputs > 1) {
        fprintf (stderr, "Standard input can only be used once.\n");
        return EXIT_USAGE;
    }
    if (stdin_inputs == 1 && pwd_src.use_stdin) {
        fprintf (stderr, "--password-stdin cannot be combined with input from standard input.\n");
        return EXIT_USAGE;
    }
    if ((pwd_file != NULL) + (pwd_fd >= 0) + (pwd_src.use_stdin ? 1 : 0) > 1) {
        fprintf (stderr, "Use only one of --password-file, --password-fd and --password-stdin.\n");
        return EXIT_USAGE;
    }
    if (opt.quiet && opt.verbose) {
        fprintf (stderr, "--quiet and --verbose are mutually exclusive.\n");
        return EXIT_USAGE;
    }
    if (kdf_arg != NULL) {
        if (g_ascii_strcasecmp (kdf_arg, "standard") == 0) {
            gtkcrypto_set_kdf_level (GTKCRYPTO_KDF_STANDARD);
        } else if (g_ascii_strcasecmp (kdf_arg, "strong") == 0) {
            gtkcrypto_set_kdf_level (GTKCRYPTO_KDF_STRONG);
        } else if (g_ascii_strcasecmp (kdf_arg, "maximum") == 0) {
            gtkcrypto_set_kdf_level (GTKCRYPTO_KDF_MAXIMUM);
        } else {
            fprintf (stderr, "Unknown --kdf level: %s (use standard, strong or maximum)\n",
                     kdf_arg);
            return EXIT_USAGE;
        }
    }
    pwd_src.file = pwd_file;
    pwd_src.fd = pwd_fd;
    show_progress = opt.verbose && isatty (STDERR_FILENO);

    int rc = 0;
    gchar *pwd = obtain_password (&pwd_src, encrypt, &rc);
    if (pwd == NULL) return rc;

    GCancellable *cancellable = interrupt_guard_begin ();
    for (guint i = 0; i < n_files && rc != EXIT_INTERRUPTED; i++) {
        int code = process_one (&opt, files[i], output_arg, pwd, cancellable);
        if (code != 0 && (rc == 0 || code == EXIT_INTERRUPTED)) rc = code;
    }
    interrupt_guard_end ();

    secure_wipe (pwd, strlen (pwd));
    gcry_free (pwd);
    return rc;
}


/* ---- Top-level dispatch ---- */

static void
print_top_help (FILE *out)
{
    fprintf (out,
        "Usage: gtkcrypto-cli SUBCOMMAND [OPTIONS] FILE...\n"
        "\n"
        "Subcommands:\n"
        "  hash      Compute (or --check) hash digests of files\n"
        "  encrypt   Encrypt files to FILE.enc\n"
        "  decrypt   Decrypt files\n"
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

    if (g_strcmp0 (sub, "hash") == 0)    return cmd_hash (argc - 1, argv + 1);
    if (g_strcmp0 (sub, "encrypt") == 0) return cmd_crypt (argc - 1, argv + 1, TRUE);
    if (g_strcmp0 (sub, "decrypt") == 0) return cmd_crypt (argc - 1, argv + 1, FALSE);

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
