#include <gtk/gtk.h>
#include <gcrypt.h>
#include "gtkcrypto.h"
#include "main.h"

#define AES256_KEY_SIZE     32
#define AES256_BLOCK_SIZE   16
#define AES256_IV_SIZE      AES256_BLOCK_SIZE
#define TAG_SIZE            AES256_BLOCK_SIZE
#define KDF_ITERATIONS      150000
#define KDF_SALT_SIZE       32

typedef struct _txt_data {
    GtkWidget *diag;
    GtkWidget *entry1;
    GtkWidget *entry2;
    GtkTextBuffer *txt_buf;
    gchar *text_from_buffer;
} TxtData;

typedef struct _crypt_data {
    gcry_cipher_hd_t hd;
    guint8 *iv;
    guint8 *salt;
    guint8 *derived_key;
} CryptData;

static void         enc_txt                     (GtkWidget      *btn,
                                                 gpointer        user_data);

static void         dec_txt                     (GtkWidget      *btn,
                                                 gpointer        user_data);

static void         load_text_from_buffer       (TxtData        *txt_data);

static gchar       *check_pwd                   (GtkEntry       *entry1,
                                                 GtkEntry       *entry2);

static gboolean     is_b64_encoded              (const gchar *text);

static gint         get_bytes_in_buffer         (GtkTextBuffer  *buf);

static void         prepare_crypto              (CryptData      *crypt_data);

static gpg_error_t  derive_and_set_cipher_data  (TxtData        *txt_data,
                                                 CryptData      *crypt_data);

static void         show_dialog_with_data       (gchar          *data);

static void         show_error_and_cleanup      (GtkWidget      *diag,
                                                 gchar          *err_msg,
                                                 CryptData      *crypt_data);


void
txt_cb (GtkWidget *btn,
        gpointer   user_data __attribute__((unused)))
{
    GtkBuilder *builder = get_builder_from_path (PARTIAL_PATH_TO_UI_FILE);
    if (builder == NULL) {
        return;
    }

    TxtData *txt_data = g_new0 (TxtData, 1);

    txt_data->diag = GTK_WIDGET(gtk_builder_get_object (builder, "text_diag"));
    GtkWidget *ok_btn = GTK_WIDGET(gtk_builder_get_object (builder, "txt_btn_ok"));
    txt_data->entry1 = GTK_WIDGET(gtk_builder_get_object (builder, "pwd_entry1_txt"));
    txt_data->entry2 = GTK_WIDGET(gtk_builder_get_object (builder, "pwd_entry2_txt"));
    txt_data->txt_buf = GTK_TEXT_BUFFER(gtk_builder_get_object (builder, "text_buf"));
    g_object_unref (builder);

    if (g_strcmp0 (gtk_widget_get_name (btn), "dectxt_btn") == 0) {
        gtk_widget_destroy (txt_data->entry2);
    }

    gtk_widget_show_all (txt_data->diag);

    if (g_strcmp0 (gtk_widget_get_name (btn), "enctxt_btn") == 0) {
        g_signal_connect (ok_btn, "clicked", G_CALLBACK (enc_txt), txt_data);
    } else {
        g_signal_connect (ok_btn, "clicked", G_CALLBACK (dec_txt), txt_data);
    }

    gint result = gtk_dialog_run (GTK_DIALOG(txt_data->diag));
    switch (result) {
        case GTK_RESPONSE_CANCEL:
        default:
            gtk_widget_destroy (txt_data->diag);
            g_free (txt_data);
            break;
    }
}


static void
enc_txt (GtkWidget *btn __attribute__((unused)),
         gpointer   user_data)
{
    CryptData *crypt_data = g_new0 (CryptData, 1);
    TxtData *txt_data = (TxtData *)user_data;

    gchar *err_msg = check_pwd (GTK_ENTRY(txt_data->entry1), GTK_ENTRY(txt_data->entry2));
    if (err_msg != NULL) {
        show_error_and_cleanup (txt_data->diag, err_msg, NULL);
        g_free (crypt_data);
        return;
    }

    gint text_size_in_bytes = get_bytes_in_buffer (txt_data->txt_buf);
    if (text_size_in_bytes == -1) {
        err_msg = g_strdup_printf ("Input data (%d input size) is too large (%d max size).\n", text_size_in_bytes, SECURE_MEMORY_POOL_SIZE);
        show_error_and_cleanup (txt_data->diag, err_msg, NULL);
        g_free (crypt_data);
        return;
    }

    load_text_from_buffer (txt_data);
    if (!g_utf8_validate (txt_data->text_from_buffer, -1, NULL)) {
        show_message_dialog (txt_data->diag, "Input is not valid utf8, exiting.", GTK_MESSAGE_ERROR);
        g_free (crypt_data);
        g_free (txt_data->text_from_buffer);
        return;
    }

    prepare_crypto (crypt_data);
    gcry_create_nonce (crypt_data->iv, AES256_IV_SIZE);
    gcry_create_nonce (crypt_data->salt, KDF_SALT_SIZE);

    gpg_error_t err = derive_and_set_cipher_data (txt_data, crypt_data);
    if (err != 0) {
        err_msg = g_strdup_printf ("%s\n", gcry_strerror (err));
        show_error_and_cleanup (txt_data->diag, err_msg, crypt_data);
        g_free (txt_data->text_from_buffer);
        gcry_cipher_close (crypt_data->hd);
        return;
    }

    guchar *enc_buf = gcry_calloc ((gsize)text_size_in_bytes, 1);
    err = gcry_cipher_encrypt (crypt_data->hd, enc_buf, (gsize)text_size_in_bytes, txt_data->text_from_buffer, (gsize)text_size_in_bytes);
    g_free (txt_data->text_from_buffer);
    if (err != 0) {
        err_msg = g_strdup_printf ("Couldn't encrypt given input: %s\n", gcry_strerror (err));
        show_error_and_cleanup (txt_data->diag, err_msg, crypt_data);
        gcry_free (enc_buf);
        gcry_cipher_close (crypt_data->hd);
        return;
    }
    gsize final_buf_size = (gsize)text_size_in_bytes + TAG_SIZE + AES256_IV_SIZE + KDF_SALT_SIZE;
    guchar *final_buf = gcry_calloc (final_buf_size, 1);
    memcpy (final_buf, crypt_data->iv, AES256_IV_SIZE);
    memcpy (final_buf + AES256_IV_SIZE, crypt_data->salt, KDF_SALT_SIZE);
    memcpy (final_buf + AES256_IV_SIZE + KDF_SALT_SIZE, enc_buf, (gsize)text_size_in_bytes);

    guint8 tag[TAG_SIZE];
    err = gcry_cipher_gettag (crypt_data->hd, tag, TAG_SIZE);
    if (err != 0) {
        err_msg = g_strdup_printf ("Couldn't get tag: %s\n", gcry_strerror (err));
        show_error_and_cleanup (txt_data->diag, err_msg, crypt_data);
        gcry_free (enc_buf);
        gcry_free (final_buf);
        gcry_cipher_close (crypt_data->hd);
        return;
    }

    gcry_cipher_close (crypt_data->hd);

    memcpy (final_buf + AES256_IV_SIZE + KDF_SALT_SIZE + (gsize)text_size_in_bytes, tag, TAG_SIZE);

    gint state = 0, save = 0, b64_encoded_data_len = 0;
    gsize data_size = (final_buf_size / 3 + 1) * 4 + 4;
    gchar *b64_encoded_buf = g_malloc0 (data_size + (data_size / 72 + 1));
    b64_encoded_data_len += (gint)g_base64_encode_step (final_buf, final_buf_size, TRUE, b64_encoded_buf, &state, &save);
    b64_encoded_data_len += (gint)g_base64_encode_close (TRUE, b64_encoded_buf + b64_encoded_data_len, &state, &save);
    b64_encoded_buf[b64_encoded_data_len] = '\0';

    show_dialog_with_data (b64_encoded_buf);

    g_free (b64_encoded_buf);
    gcry_free (final_buf);
    gcry_free (enc_buf);

    gcry_free (crypt_data->derived_key);
    gcry_free (crypt_data->iv);
    gcry_free (crypt_data->salt);
    g_free (crypt_data);

    gtk_dialog_response (GTK_DIALOG(txt_data->diag), GTK_RESPONSE_CANCEL);
}


static void
dec_txt (GtkWidget *btn __attribute__((unused)),
         gpointer   user_data)
{
    CryptData *crypt_data = g_new0 (CryptData, 1);
    TxtData *txt_data = (TxtData *)user_data;

    gchar *err_msg = check_pwd (GTK_ENTRY(txt_data->entry1), NULL);
    if (err_msg != NULL) {
        show_error_and_cleanup (txt_data->diag, err_msg, NULL);
        g_free (crypt_data);
        return;
    }

    gint num_of_chars = gtk_text_buffer_get_char_count (txt_data->txt_buf);
    if ((num_of_chars / 4 * 3) > SECURE_MEMORY_POOL_SIZE) {
        err_msg = g_strdup_printf ("Input data (%d input size) is too large (%d max size).\n", num_of_chars / 4 * 3, SECURE_MEMORY_POOL_SIZE);
        show_error_and_cleanup (txt_data->diag, err_msg, NULL);
        g_free (crypt_data);
        return;
    }

    load_text_from_buffer (txt_data);
    if (!g_str_is_ascii (txt_data->text_from_buffer)) {
        err_msg = g_strdup ("The input data contains invalid chars (only ASCII chars allowed)");
        show_error_and_cleanup (txt_data->diag, err_msg, NULL);
        g_free (crypt_data);
        g_free (txt_data->text_from_buffer);
        return;
    }
    if (!is_b64_encoded (txt_data->text_from_buffer)) {
        err_msg = g_strdup ("The given input is NOT base64 encoded");
        show_error_and_cleanup (txt_data->diag, err_msg, NULL);
        g_free (crypt_data);
        g_free (txt_data->text_from_buffer);
        return;
    }

    prepare_crypto (crypt_data);

    gsize out_len = 0;
    guchar *encrypted_buf = g_base64_decode (txt_data->text_from_buffer, &out_len);
    g_free (txt_data->text_from_buffer);

    memcpy (crypt_data->iv, encrypted_buf, AES256_IV_SIZE);
    memcpy (crypt_data->salt, encrypted_buf + AES256_IV_SIZE, KDF_SALT_SIZE);

    gpg_error_t err = derive_and_set_cipher_data (txt_data, crypt_data);
    if (err != 0) {
        err_msg = g_strdup_printf ("%s\n", gcry_strerror (err));
        show_error_and_cleanup (txt_data->diag, err_msg, crypt_data);
        g_free (encrypted_buf);
        gcry_cipher_close (crypt_data->hd);
        return;
    }

    gsize enc_body_len = out_len - AES256_IV_SIZE - KDF_SALT_SIZE - TAG_SIZE;
    guchar *enc_body = g_malloc0 (enc_body_len);
    memcpy (enc_body, encrypted_buf + AES256_IV_SIZE + KDF_SALT_SIZE, enc_body_len);
    gchar *plain_buf = gcry_calloc_secure (enc_body_len, 1);
    gcry_cipher_decrypt (crypt_data->hd, plain_buf, enc_body_len, enc_body, enc_body_len);

    guint8 tag[TAG_SIZE];
    memcpy (tag, encrypted_buf + (out_len - TAG_SIZE), TAG_SIZE);
    err = gcry_cipher_checktag (crypt_data->hd, tag, TAG_SIZE);
    if (err != 0) {
        err_msg = g_strdup_printf ("Error: %s\nEither the password is wrong or the data is corrupted.\n", gcry_strerror (err));
        show_error_and_cleanup (txt_data->diag, err_msg, crypt_data);
        g_free (encrypted_buf);
        g_free (enc_body);
        gcry_free (plain_buf);
        gcry_cipher_close (crypt_data->hd);
        return;
    }

    gcry_cipher_close (crypt_data->hd);

    show_dialog_with_data (plain_buf);

    g_free (encrypted_buf);
    g_free (enc_body);
    gcry_free (plain_buf);

    gcry_free (crypt_data->derived_key);
    gcry_free (crypt_data->iv);
    gcry_free (crypt_data->salt);
    g_free (crypt_data);

    gtk_dialog_response (GTK_DIALOG(txt_data->diag), GTK_RESPONSE_CANCEL);
}


static gchar *
check_pwd (GtkEntry *entry1,
           GtkEntry *entry2)
{
    if (gtk_entry_get_text_length (entry1) < 8) {
        return g_strdup ("Password must be at least 8 characters long\n");
    }

    if (entry2 != NULL && g_strcmp0 (gtk_entry_get_text (entry1), gtk_entry_get_text (entry2)) != 0) {
        return g_strdup ("Passwords do not match\n");
    }

    return NULL;
}


static gboolean
is_b64_encoded (const gchar *text)
{
    static const guint8 b64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    gsize data_len = strlen (text), found = 0, b64_alphabet_len = sizeof(b64_alphabet);

    for (gint i = 0; i < data_len; i++) {
        for (gint j = 0; j < b64_alphabet_len; j++) {
            if (text[i] == b64_alphabet[j] || text[i] == '=' || text[i] == '\n') {
                found++;
                break;
            }
        }
    }
    if (found == data_len) {
        return TRUE;
    }

    return FALSE;
}


static void
show_error_and_cleanup (GtkWidget *diag, gchar *err_msg, CryptData *crypt_data)
{
    show_message_dialog (diag, err_msg, GTK_MESSAGE_ERROR);
    g_free (err_msg);
    if (crypt_data != NULL) {
        gcry_free (crypt_data->iv);
        gcry_free (crypt_data->salt);
        gcry_free (crypt_data->derived_key);
        g_free (crypt_data);
    }
}


static void
load_text_from_buffer (TxtData *txt_data)
{
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds (txt_data->txt_buf, &start, &end);
    txt_data->text_from_buffer = gtk_text_buffer_get_text (txt_data->txt_buf, &start, &end, FALSE);
}


static gint
get_bytes_in_buffer (GtkTextBuffer *buf)
{
    gint total_bytes = 0, done_lines = 0;
    GtkTextIter iter;
    gint lines = gtk_text_buffer_get_line_count (buf);

    while (lines > done_lines) {
        gtk_text_buffer_get_start_iter (buf, &iter);
        total_bytes += gtk_text_iter_get_bytes_in_line (&iter);
        if (total_bytes > SECURE_MEMORY_POOL_SIZE) {
            return -1;
        }
        gtk_text_iter_forward_line (&iter);
        done_lines++;
    }

    return total_bytes + 1; // +1 for the null-terminator
}


static void
prepare_crypto (CryptData *crypt_data)
{
    gint algo = gcry_cipher_map_name ("aes256");

    crypt_data->iv = gcry_calloc (AES256_IV_SIZE, 1);
    crypt_data->salt = gcry_calloc (KDF_SALT_SIZE, 1);
    crypt_data->derived_key = gcry_calloc_secure (AES256_KEY_SIZE, 1);

    gcry_cipher_open (&crypt_data->hd, algo, GCRY_CIPHER_MODE_GCM, 0);
}


static gpg_error_t
derive_and_set_cipher_data (TxtData   *txt_data,
                            CryptData *crypt_data)
{
    gpg_error_t err = gcry_kdf_derive (gtk_entry_get_text (GTK_ENTRY (txt_data->entry1)), gtk_entry_get_text_length (GTK_ENTRY (txt_data->entry1)) + 1,
                                       GCRY_KDF_PBKDF2, GCRY_MD_SHA3_256,
                                       crypt_data->salt, KDF_SALT_SIZE,
                                       KDF_ITERATIONS,
                                       AES256_KEY_SIZE, crypt_data->derived_key);
    if (err != 0) {
        g_printerr ("Couldn't derive key\n");
        return err;
    }

    err = gcry_cipher_setkey (crypt_data->hd, crypt_data->derived_key, AES256_KEY_SIZE);
    if (err != 0) {
        g_printerr ("Couldn't set cipher key\n");
        return err;
    }

    err = gcry_cipher_setiv (crypt_data->hd, crypt_data->iv, AES256_IV_SIZE);
    if (err != 0) {
        g_printerr ("Couldn't set cipher iv\n");
        return err;
    }

    return err;
}


static void
show_dialog_with_data (gchar *data)
{
    GtkBuilder *builder = get_builder_from_path (PARTIAL_PATH_TO_UI_FILE);
    if (builder == NULL) {
        return;
    }

    GtkWidget *diag = GTK_WIDGET(gtk_builder_get_object (builder, "data_diag"));
    GtkTextBuffer *text_buf = GTK_TEXT_BUFFER(gtk_builder_get_object(builder,"data_text_buf"));
    g_object_unref (builder);

    gtk_widget_show_all (diag);

    gtk_text_buffer_set_text (text_buf, data, -1);

    gint result = gtk_dialog_run (GTK_DIALOG(diag));
    switch (result) {
        case GTK_RESPONSE_OK:
            break;
        default:
            break;
    }
    gtk_widget_destroy (diag);
}