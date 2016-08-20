#pragma once

#define SIG_MAXLEN 4096

#define VALID_SIGNATURE ((gpointer) 1)
#define SIGN_OK ((gpointer) 0)
#define GPGME_ERROR ((gpointer) -1)
#define FILE_OPEN_ERROR ((gpointer) -2)
#define FILE_WRITE_ERROR ((gpointer) -3)
#define MEMORY_ALLOCATION_ERROR ((gpointer) -4)
#define NO_GPG_KEYS_AVAILABLE ((gpointer) -5)
#define BAD_SIGNATURE ((gpointer) -6)

typedef struct _key_info_t {
    gchar *name;
    gchar *email;
    gchar *key_id;
    gchar *key_fpr;
} KeyInfo;

GSList *get_available_keys (void);

gpointer sign_file (const gchar *input_file_path, const gchar *fpr);

gpointer verify_signature (const gchar *detached_signature_path, const gchar *signed_file_path);
