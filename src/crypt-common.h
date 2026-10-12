#pragma once

#include <gio/gio.h>
#include <glib.h>
#include <gcrypt.h>

#define FILE_BUFFER                 (1024 * 1024)

#define GTKCRYPTO_V3_HEADER_SIZE    80
#define GTKCRYPTO_SALT_SIZE         32
#define GTKCRYPTO_NONCE_SIZE        12
#define GTKCRYPTO_TAG_SIZE          16
#define GTKCRYPTO_KEY_SIZE          32

#define GTKCRYPTO_ARGON2_TIME       2
#define GTKCRYPTO_ARGON2_MEMORY_KIB 19456
#define GTKCRYPTO_ARGON2_LANES      1

/* Argon2id cost used when *writing* GTC3 data. The parameters are stored in
 * every header, so decryption works regardless of the level in effect. */
typedef enum {
    GTKCRYPTO_KDF_STANDARD = 0,   /* t=2, m=19 MiB, p=1  (default) */
    GTKCRYPTO_KDF_STRONG,         /* t=3, m=64 MiB, p=4 */
    GTKCRYPTO_KDF_MAXIMUM         /* t=4, m=256 MiB, p=4 */
} GtkcryptoKdfLevel;

typedef struct {
    guint32 time;
    guint32 memory_kib;
    guint32 lanes;
} GtkcryptoKdfParams;

void              gtkcrypto_set_kdf_level (GtkcryptoKdfLevel level);
GtkcryptoKdfLevel gtkcrypto_get_kdf_level (void);
void              gtkcrypto_kdf_params_current (GtkcryptoKdfParams *params);

/* The fixed-size GTC3 header (docs/file-format.md). It is the single place
 * that knows the byte layout; files and text containers both use it. The
 * encoded form is also the AES-GCM additional authenticated data. */
typedef struct {
    GtkcryptoKdfParams kdf;
    guint64            plaintext_size;
    guint8             salt[GTKCRYPTO_SALT_SIZE];
    guint8             nonce[GTKCRYPTO_NONCE_SIZE];
} GtkcryptoV3Header;

/* Fills KDF parameters (current level), random salt and nonce. */
void     gtkcrypto_v3_header_init   (GtkcryptoV3Header *header,
                                     guint64 plaintext_size);
void     gtkcrypto_v3_header_encode (const GtkcryptoV3Header *header,
                                     guint8 out[GTKCRYPTO_V3_HEADER_SIZE]);
/* FALSE when magic, version, algorithm IDs, lengths or reserved bytes are not
 * exactly what this implementation supports. KDF costs are bounds-checked by
 * gtkcrypto_argon2id_derive(). */
gboolean gtkcrypto_v3_header_decode (const guint8 *in, gsize len,
                                     GtkcryptoV3Header *header);

#define GTKCRYPTO_V2_HEADER_SIZE    62
#define GTKCRYPTO_LEGACY_HMAC_SIZE  64
#define GTKCRYPTO_LEGACY_KDF_V1     100000
#define GTKCRYPTO_LEGACY_KDF_V2     600000

/* Legacy text-container constants. */
#define AES256_KEY_SIZE GTKCRYPTO_KEY_SIZE
#define AES256_IV_SIZE 16
#define KDF_SALT_SIZE GTKCRYPTO_SALT_SIZE
#define TAG_SIZE GTKCRYPTO_TAG_SIZE
#define KDF_ITERATIONS GTKCRYPTO_LEGACY_KDF_V2

typedef enum {
    GTKCRYPTO_ERROR_INVALID_ARGUMENT,
    GTKCRYPTO_ERROR_EXISTS,
    GTKCRYPTO_ERROR_INVALID_FORMAT,
    GTKCRYPTO_ERROR_UNSUPPORTED,
    GTKCRYPTO_ERROR_AUTHENTICATION,
    GTKCRYPTO_ERROR_IO,
    GTKCRYPTO_ERROR_CRYPTO,
    GTKCRYPTO_ERROR_CANCELLED,
} GtkcryptoError;

#define GTKCRYPTO_ERROR (gtkcrypto_error_quark ())
GQuark gtkcrypto_error_quark (void);

typedef struct {
    gchar *path;
    gint fd;
    gchar *destination;
    gboolean overwrite;
} GtkcryptoAtomicOutput;

gboolean gtkcrypto_argon2id_derive (const guint8 *password,
                                    gsize password_len,
                                    const guint8 salt[GTKCRYPTO_SALT_SIZE],
                                    guint32 time_cost,
                                    guint32 memory_kib,
                                    guint32 lanes,
                                    guint8 key[GTKCRYPTO_KEY_SIZE],
                                    GError **error);

gboolean gtkcrypto_pbkdf2_derive (const guint8 *password,
                                  gsize password_len,
                                  const guint8 *salt,
                                  gsize salt_len,
                                  guint iterations,
                                  gsize key_len,
                                  guint8 *key,
                                  GError **error);

gboolean gtkcrypto_atomic_output_open (GtkcryptoAtomicOutput *output,
                                       const gchar *destination,
                                       gboolean overwrite,
                                       GError **error);
gboolean gtkcrypto_atomic_output_commit (GtkcryptoAtomicOutput *output,
                                         GError **error);
void gtkcrypto_atomic_output_abort (GtkcryptoAtomicOutput *output);

gboolean gtkcrypto_read_full (gint fd, void *buffer, gsize length,
                              GCancellable *cancellable, GError **error);
gboolean gtkcrypto_write_full (gint fd, const void *buffer, gsize length,
                               GCancellable *cancellable, GError **error);
gboolean gtkcrypto_check_cancelled (GCancellable *cancellable, GError **error);

/* Optional per-thread progress reporting. A caller installs a callback on the
 * thread that runs gtkcrypto_encrypt_file()/gtkcrypto_decrypt_file(); the core
 * calls it after every processed chunk with the plaintext bytes done so far
 * and the total. Pass NULL to remove it. Legacy formats do not report. */
typedef void (*GtkcryptoProgressFunc) (guint64 done, guint64 total,
                                       gpointer user_data);
void gtkcrypto_set_progress    (GtkcryptoProgressFunc func, gpointer user_data);
void gtkcrypto_report_progress (guint64 done, guint64 total);

void gtkcrypto_secure_clear (gpointer data, gsize length);

GBytes *gtkcrypto_encrypt_bytes_v3 (const guint8 *plaintext,
                                    gsize plaintext_len,
                                    const guint8 *password,
                                    gsize password_len,
                                    GError **error);
GBytes *gtkcrypto_decrypt_bytes_v3 (const guint8 *container,
                                    gsize container_len,
                                    const guint8 *password,
                                    gsize password_len,
                                    GError **error);
