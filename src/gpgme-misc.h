#ifndef GPGME_MISC_H_H
#define GPGME_MISC_H_H

#define SIG_MAXLEN 4096

#define SIGN_OK ((gpointer) 0)
#define GPGME_ERROR ((gpointer) -1)
#define FILE_OPEN_ERROR ((gpointer) -2)
#define FILE_WRITE_ERROR ((gpointer) -3)
#define MEMORY_ALLOCATION_ERROR ((gpointer) -4)

typedef struct _key_info_t {
    gchar *name;
    gchar *email;
    gchar *key_id;
    gchar *key_fpr;
} KeyInfo;

GSList *get_available_keys (void);

gpointer sign_file (const gchar *input_file_path, const gchar *fpr);

#endif
