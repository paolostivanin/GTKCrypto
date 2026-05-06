#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>

#include "../hash.h"
#include "../gtkcrypto.h"
#include "../encrypt-files-cb.h"
#include "../decrypt-files-cb.h"

#define GCRYPT_MIN_VER  "1.7.0"
#define SECMEM_SIZE     32768
#define MIN_PWD_LEN     8

#define EXIT_USAGE 2

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

typedef struct {
    const gchar *cli_name;
    const gchar *internal_name;
} NameMap;

/* The core API still takes legacy widget-name strings (GTK 3 holdover);
   the CLI translates clean user-facing names into them. */
static const NameMap CIPHER_NAMES[] = {
    { "aes",      "aes_rbtn_widget"      },
    { "twofish",  "twofish_rbtn_widget"  },
    { "serpent",  "serpent_rbtn_widget"  },
    { "camellia", "camellia_rbtn_widget" },
};

static const NameMap MODE_NAMES[] = {
    { "gcm", "gcm_rbtn_widget" },
    { "ctr", "ctr_rbtn_widget" },
    { "cbc", "cbc_rbtn_widget" },
};


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

static const gchar *
lookup_internal (const NameMap *map, gsize n, const gchar *name)
{
    for (gsize i = 0; i < n; i++) {
        if (g_ascii_strcasecmp (name, map[i].cli_name) == 0) {
            return map[i].internal_name;
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

static gchar *
join_namemap (const NameMap *map, gsize n)
{
    GString *s = g_string_new (NULL);
    for (gsize i = 0; i < n; i++) {
        if (i > 0) g_string_append (s, ", ");
        g_string_append (s, map[i].cli_name);
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

    if (strlen (pwd) < MIN_PWD_LEN) {
        fprintf (stderr, "Password must be at least %d characters.\n", MIN_PWD_LEN);
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
    int rc = 0;
    for (gsize i = 0; algos[i] != NULL; i++) {
        const gchar *name = g_strstrip (algos[i]);
        if (*name == '\0') continue;
        const HashName *hn = lookup_hash (name);
        if (hn == NULL) {
            fprintf (stderr, "Unknown algorithm: %s\nValid: %s\n", name, valid);
            return EXIT_USAGE;
        }
        g_autofree gchar *hash = get_file_hash (path, hn->gcry_id, hn->digest_size);
        if (hash == NULL) {
            fprintf (stderr, "Failed to compute %s of %s\n", hn->cli_name, path);
            rc = 1;
            continue;
        }
        printf ("%s  %s\n", hash, path);
    }
    return rc;
}


/* ---- Subcommand: encrypt ---- */

static int
cmd_encrypt (int argc, char **argv)
{
    g_autofree gchar *cipher_arg = NULL;
    g_autofree gchar *mode_arg = NULL;
    g_autofree gchar *pwd_file = NULL;
    g_auto(GStrv) files = NULL;

    GOptionEntry entries[] = {
        { "cipher", 'c', 0, G_OPTION_ARG_STRING, &cipher_arg,
          "Cipher: aes (default), twofish, serpent, camellia.", "NAME" },
        { "mode", 'm', 0, G_OPTION_ARG_STRING, &mode_arg,
          "Mode: gcm (default), ctr, cbc.", "NAME" },
        { "password-file", 'p', 0, G_OPTION_ARG_FILENAME, &pwd_file,
          "Read password from PATH (first line). Otherwise prompt interactively.", "PATH" },
        { G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &files, NULL, NULL },
        { 0 },
    };

    g_autoptr(GOptionContext) ctx = g_option_context_new ("FILE");
    g_option_context_set_summary (ctx,
        "Encrypt FILE in place; the result is written to FILE.enc next to the source.\n"
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

    const gchar *cipher = lookup_internal (CIPHER_NAMES, G_N_ELEMENTS (CIPHER_NAMES),
                                           cipher_arg ? cipher_arg : "aes");
    if (cipher == NULL) {
        g_autofree gchar *valid = join_namemap (CIPHER_NAMES, G_N_ELEMENTS (CIPHER_NAMES));
        fprintf (stderr, "Unknown cipher: %s\nValid: %s\n", cipher_arg, valid);
        return EXIT_USAGE;
    }
    const gchar *mode = lookup_internal (MODE_NAMES, G_N_ELEMENTS (MODE_NAMES),
                                         mode_arg ? mode_arg : "gcm");
    if (mode == NULL) {
        g_autofree gchar *valid = join_namemap (MODE_NAMES, G_N_ELEMENTS (MODE_NAMES));
        fprintf (stderr, "Unknown mode: %s\nValid: %s\n", mode_arg, valid);
        return EXIT_USAGE;
    }

    gchar *pwd = obtain_password (pwd_file, TRUE);
    if (pwd == NULL) return 1;

    gpointer ret = encrypt_file (files[0], pwd, cipher, mode);
    secure_wipe (pwd, strlen (pwd));
    gcry_free (pwd);

    if (ret != NULL) {
        fprintf (stderr, "%s\n", (gchar *)ret);
        g_free (ret);
        return 1;
    }
    return 0;
}


/* ---- Subcommand: decrypt ---- */

static int
cmd_decrypt (int argc, char **argv)
{
    g_autofree gchar *pwd_file = NULL;
    gboolean delete_after = FALSE;
    g_auto(GStrv) files = NULL;

    GOptionEntry entries[] = {
        { "password-file", 'p', 0, G_OPTION_ARG_FILENAME, &pwd_file,
          "Read password from PATH (first line). Otherwise prompt interactively.", "PATH" },
        { "delete", 'd', 0, G_OPTION_ARG_NONE, &delete_after,
          "Delete the encrypted FILE after a successful decryption.", NULL },
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

    gpointer ret = decrypt_file (files[0], pwd);
    secure_wipe (pwd, strlen (pwd));
    gcry_free (pwd);

    if (ret != NULL) {
        fprintf (stderr, "%s\n", (gchar *)ret);
        g_free (ret);
        return 1;
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
