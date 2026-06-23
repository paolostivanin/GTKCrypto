#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gcrypt.h>
#include <string.h>
#include <unistd.h>

#include "crypt-common.h"
#include "decrypt-files-cb.h"
#include "encrypt-files-cb.h"
#include "gtkcrypto.h"
#include "hash.h"

static gchar *test_dir;
static const guint8 password[] = "correct horse battery staple";

static gchar *
path_for (const gchar *name)
{
    return g_build_filename (test_dir, name, NULL);
}

static void
write_file (const gchar *path, const guint8 *data, gsize length)
{
    g_assert_true (g_file_set_contents (path, (const gchar *)data,
                                        (gssize)length, NULL));
}

static GBytes *
read_file (const gchar *path)
{
    gchar *data = NULL;
    gsize length = 0;
    g_assert_true (g_file_get_contents (path, &data, &length, NULL));
    return g_bytes_new_take (data, length);
}

static void
assert_files_equal (const gchar *a, const gchar *b)
{
    g_autoptr(GBytes) first = read_file (a);
    g_autoptr(GBytes) second = read_file (b);
    g_assert_true (g_bytes_equal (first, second));
}

static void
test_hash_boundaries (void)
{
    g_autofree gchar *empty = path_for ("empty");
    g_autofree gchar *block = path_for ("64m");
    write_file (empty, NULL, 0);
    gint fd = g_open (block, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    g_assert_cmpint (fd, >=, 0);
    g_assert_cmpint (ftruncate (fd, 64 * 1024 * 1024), ==, 0);
    close (fd);

    g_autofree gchar *empty_hash =
        get_file_hash (empty, GCRY_MD_SHA256, SHA256_DIGEST_SIZE);
    g_autofree gchar *block_hash =
        get_file_hash (block, GCRY_MD_SHA256, SHA256_DIGEST_SIZE);
    g_assert_cmpstr (empty_hash, ==,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    g_assert_cmpstr (block_hash, ==,
        "3b6a07d0d404fab4e23b6d34bc6696a6a312dd92821332385e5af7c01c421351");
}

static void
test_v3_roundtrip_and_failures (void)
{
    const guint8 payload[] = { 0, 1, 2, 3, 0xff, 'G', 'T', 'C' };
    g_autofree gchar *plain = path_for ("données");
    g_autofree gchar *encrypted = path_for ("données.enc");
    g_autofree gchar *recovered = path_for ("résultat");
    write_file (plain, payload, sizeof payload);

    g_autoptr(GError) error = NULL;
    g_assert_true (gtkcrypto_encrypt_file (
        plain, encrypted, password, sizeof password - 1,
        FALSE, NULL, &error));
    g_assert_no_error (error);

    g_autoptr(GBytes) bytes = read_file (encrypted);
    gsize encrypted_len;
    const guint8 *encrypted_data = g_bytes_get_data (bytes, &encrypted_len);
    g_assert_cmpuint (encrypted_len, ==,
                      GTKCRYPTO_V3_HEADER_SIZE + sizeof payload +
                      GTKCRYPTO_TAG_SIZE);
    g_assert_cmpmem (encrypted_data, 4, "GTC3", 4);

    g_assert_true (gtkcrypto_decrypt_file (
        encrypted, recovered, password, sizeof password - 1,
        FALSE, NULL, &error));
    g_assert_no_error (error);
    assert_files_equal (plain, recovered);

    const guint8 marker[] = "keep me";
    write_file (recovered, marker, sizeof marker - 1);
    const guint8 wrong[] = "wrong password";
    g_assert_false (gtkcrypto_decrypt_file (
        encrypted, recovered, wrong, sizeof wrong - 1,
        TRUE, NULL, &error));
    g_assert_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_AUTHENTICATION);
    g_clear_error (&error);
    g_autoptr(GBytes) preserved = read_file (recovered);
    gsize preserved_len;
    const guint8 *preserved_data = g_bytes_get_data (preserved,
                                                     &preserved_len);
    g_assert_cmpmem (preserved_data, preserved_len,
                     marker, sizeof marker - 1);

    g_assert_false (gtkcrypto_encrypt_file (
        plain, encrypted, password, sizeof password - 1,
        FALSE, NULL, &error));
    g_assert_error (error, GTKCRYPTO_ERROR, GTKCRYPTO_ERROR_EXISTS);
}

static void
test_v3_empty_and_text (void)
{
    g_autofree gchar *empty = path_for ("zero");
    g_autofree gchar *encrypted = path_for ("zero.enc");
    g_autofree gchar *recovered = path_for ("zero.out");
    write_file (empty, NULL, 0);

    g_autoptr(GError) error = NULL;
    g_assert_true (gtkcrypto_encrypt_file (
        empty, encrypted, password, sizeof password - 1,
        FALSE, NULL, &error));
    g_assert_true (gtkcrypto_decrypt_file (
        encrypted, recovered, password, sizeof password - 1,
        FALSE, NULL, &error));
    assert_files_equal (empty, recovered);

    const guint8 text[] = "Unicode: 🔐 café";
    g_autoptr(GBytes) container = gtkcrypto_encrypt_bytes_v3 (
        text, sizeof text - 1, password, sizeof password - 1, &error);
    g_assert_nonnull (container);
    gsize container_len;
    const guint8 *container_data = g_bytes_get_data (container,
                                                     &container_len);
    g_autoptr(GBytes) plaintext = gtkcrypto_decrypt_bytes_v3 (
        container_data, container_len, password, sizeof password - 1,
        &error);
    g_assert_nonnull (plaintext);
    gsize plaintext_len;
    const guint8 *plaintext_data = g_bytes_get_data (plaintext,
                                                     &plaintext_len);
    g_assert_cmpmem (plaintext_data, plaintext_len - 1,
                     text, sizeof text - 1);
}

static void
create_v2_gcm_fixture (const gchar *path,
                       const guint8 *plaintext,
                       gsize plaintext_len)
{
    guint8 header[GTKCRYPTO_V2_HEADER_SIZE] = { 0 };
    memcpy (header, "GTC", 3);
    header[3] = 2;
    header[20] = 12;
    for (guint i = 0; i < 12; i++) header[4 + i] = (guint8)i;
    for (guint i = 0; i < 32; i++) header[21 + i] = (guint8)(i + 1);
    gint algo = GCRY_CIPHER_AES256;
    gint mode = GCRY_CIPHER_MODE_GCM;
    memcpy (header + 53, &algo, 4);
    memcpy (header + 57, &mode, 4);

    guint8 derived[GTKCRYPTO_KEY_SIZE + 64];
    g_assert_true (gtkcrypto_pbkdf2_derive (
        password, sizeof password, header + 21, 32,
        GTKCRYPTO_LEGACY_KDF_V2, sizeof derived, derived, NULL));
    g_autofree guint8 *output =
        g_malloc (sizeof header + plaintext_len + GTKCRYPTO_TAG_SIZE);
    memcpy (output, header, sizeof header);

    gcry_cipher_hd_t cipher;
    g_assert_cmpint (gcry_cipher_open (&cipher, algo,
                                      GCRY_CIPHER_MODE_GCM, 0), ==, 0);
    g_assert_cmpint (gcry_cipher_setkey (cipher, derived,
                                        GTKCRYPTO_KEY_SIZE), ==, 0);
    g_assert_cmpint (gcry_cipher_setiv (cipher, header + 4, 12), ==, 0);
    gcry_cipher_final (cipher);
    g_assert_cmpint (gcry_cipher_encrypt (
        cipher, output + sizeof header, plaintext_len,
        plaintext, plaintext_len), ==, 0);
    g_assert_cmpint (gcry_cipher_gettag (
        cipher, output + sizeof header + plaintext_len,
        GTKCRYPTO_TAG_SIZE), ==, 0);
    gcry_cipher_close (cipher);
    gtkcrypto_secure_clear (derived, sizeof derived);
    write_file (path, output,
                sizeof header + plaintext_len + GTKCRYPTO_TAG_SIZE);
}

static void
test_v2_compatibility (void)
{
    const guint8 payload[] = "legacy v2 payload";
    g_autofree gchar *encrypted = path_for ("legacy-v2.enc");
    g_autofree gchar *recovered = path_for ("legacy-v2.out");
    create_v2_gcm_fixture (encrypted, payload, sizeof payload - 1);

    g_autoptr(GError) error = NULL;
    g_assert_true (gtkcrypto_decrypt_file (
        encrypted, recovered, password, sizeof password - 1,
        FALSE, NULL, &error));
    g_assert_no_error (error);
    g_autoptr(GBytes) result = read_file (recovered);
    gsize length;
    const guint8 *data = g_bytes_get_data (result, &length);
    g_assert_cmpmem (data, length, payload, sizeof payload - 1);
}

static void
create_v1_ctr_fixture (const gchar *path,
                       const guint8 *plaintext,
                       gsize plaintext_len)
{
    guint8 header[72] = { 0 };
    for (guint i = 0; i < 16; i++) header[i] = (guint8)(0xa0 + i);
    guint64 iv_size = 16;
    memcpy (header + 16, &iv_size, sizeof iv_size);
    for (guint i = 0; i < 32; i++) header[24 + i] = (guint8)(0x40 + i);
    gint algo = GCRY_CIPHER_AES256;
    gint mode = GCRY_CIPHER_MODE_CTR;
    memcpy (header + 56, &algo, 4);
    memcpy (header + 60, &mode, 4);

    guint8 derived[GTKCRYPTO_KEY_SIZE + 64];
    g_assert_true (gtkcrypto_pbkdf2_derive (
        password, sizeof password, header + 24, 32,
        GTKCRYPTO_LEGACY_KDF_V1, sizeof derived, derived, NULL));

    gsize authenticated_len = sizeof header + plaintext_len;
    g_autofree guint8 *output =
        g_malloc0 (authenticated_len + GTKCRYPTO_LEGACY_HMAC_SIZE);
    memcpy (output, header, sizeof header);

    gcry_cipher_hd_t cipher;
    g_assert_cmpint (gcry_cipher_open (&cipher, algo,
                                      GCRY_CIPHER_MODE_CTR, 0), ==, 0);
    g_assert_cmpint (gcry_cipher_setkey (cipher, derived,
                                        GTKCRYPTO_KEY_SIZE), ==, 0);
    g_assert_cmpint (gcry_cipher_setctr (cipher, header, 16), ==, 0);
    g_assert_cmpint (gcry_cipher_encrypt (
        cipher, output + sizeof header, plaintext_len,
        plaintext, plaintext_len), ==, 0);
    gcry_cipher_close (cipher);

    gcry_mac_hd_t mac;
    g_assert_cmpint (gcry_mac_open (&mac, GCRY_MAC_HMAC_SHA3_512,
                                   0, NULL), ==, 0);
    g_assert_cmpint (gcry_mac_setkey (mac, derived + GTKCRYPTO_KEY_SIZE,
                                     64), ==, 0);
    g_assert_cmpint (gcry_mac_write (mac, output, authenticated_len), ==, 0);
    gsize mac_len = GTKCRYPTO_LEGACY_HMAC_SIZE;
    g_assert_cmpint (gcry_mac_read (
        mac, output + authenticated_len, &mac_len), ==, 0);
    gcry_mac_close (mac);
    gtkcrypto_secure_clear (derived, sizeof derived);
    write_file (path, output,
                authenticated_len + GTKCRYPTO_LEGACY_HMAC_SIZE);
}

static void
test_v1_compatibility (void)
{
    const guint8 payload[] = "legacy v1 payload";
    g_autofree gchar *encrypted = path_for ("legacy-v1.enc");
    g_autofree gchar *recovered = path_for ("legacy-v1.out");
    create_v1_ctr_fixture (encrypted, payload, sizeof payload - 1);

    g_autoptr(GError) error = NULL;
    g_assert_true (gtkcrypto_decrypt_file (
        encrypted, recovered, password, sizeof password - 1,
        FALSE, NULL, &error));
    g_assert_no_error (error);
    g_autoptr(GBytes) result = read_file (recovered);
    gsize length;
    const guint8 *data = g_bytes_get_data (result, &length);
    g_assert_cmpmem (data, length, payload, sizeof payload - 1);
}

int
main (int argc, char **argv)
{
    g_test_init (&argc, &argv, NULL);
    g_assert_nonnull (gcry_check_version ("1.10.1"));
    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    GError *error = NULL;
    test_dir = g_dir_make_tmp ("gtkcrypto-test-XXXXXX", &error);
    g_assert_no_error (error);

    g_test_add_func ("/hash/boundaries", test_hash_boundaries);
    g_test_add_func ("/crypto/v3-roundtrip-failures",
                     test_v3_roundtrip_and_failures);
    g_test_add_func ("/crypto/v3-empty-text", test_v3_empty_and_text);
    g_test_add_func ("/crypto/v2-compatibility", test_v2_compatibility);
    g_test_add_func ("/crypto/v1-compatibility", test_v1_compatibility);
    return g_test_run ();
}
