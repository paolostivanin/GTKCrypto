#ifndef CRYPT_H
#define CRYPT_H

#define ROUNDS 50000
#define MAX_IV_SIZE 16
#define SALT_SIZE 32
#define HMAC_KEY_SIZE 32

typedef struct header_metadata_t {
    guint8 iv[MAX_IV_SIZE];
    gsize iv_size;
    guint8 salt[SALT_SIZE];
    gint algo;
    gint algo_mode;
    guint8 padding_value;
} Metadata;

typedef struct key_t {
    guchar *derived_key;
    guchar *crypto_key;
    guchar *hmac_key;
} CryptoKeys;

gboolean setup_keys (const gchar *pwd, gsize algo_key_len, Metadata *header_metadata, CryptoKeys *encryption_keys);

void set_label_message (GtkWidget *message_label, const gchar *message);

void secure_file_delete (const gchar *file_path);

#endif
