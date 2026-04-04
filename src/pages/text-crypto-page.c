#include <gcrypt.h>
#include <string.h>
#include "text-crypto-page.h"
#include "../crypt-common.h"

struct _GtkcryptoTextCryptoPage {
    GtkBox parent_instance;

    AdwViewStack *view_stack;

    /* Encrypt */
    GtkTextBuffer           *enc_input_buf;
    AdwPasswordEntryRow     *enc_pwd_row;
    AdwPasswordEntryRow     *enc_pwd_confirm_row;
    GtkWidget               *enc_btn;
    GtkTextBuffer           *enc_output_buf;
    AdwToastOverlay         *enc_toast_overlay;
    GtkSpinner              *enc_spinner;

    /* Decrypt */
    GtkTextBuffer           *dec_input_buf;
    AdwPasswordEntryRow     *dec_pwd_row;
    GtkWidget               *dec_btn;
    GtkTextBuffer           *dec_output_buf;
    AdwToastOverlay         *dec_toast_overlay;
    GtkSpinner              *dec_spinner;
};

G_DEFINE_TYPE (GtkcryptoTextCryptoPage, gtkcrypto_text_crypto_page, GTK_TYPE_BOX)


static void
show_toast (AdwToastOverlay *overlay, const gchar *msg)
{
    adw_toast_overlay_add_toast (overlay, adw_toast_new (msg));
}


static gchar *
get_buffer_text (GtkTextBuffer *buf)
{
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds (buf, &start, &end);
    return gtk_text_buffer_get_text (buf, &start, &end, FALSE);
}


static gboolean
is_b64_encoded (const gchar *text)
{
    static const guint8 b64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    gsize data_len = strlen (text), found = 0, b64_alphabet_len = sizeof(b64_alphabet);

    for (gsize i = 0; i < data_len; i++) {
        for (gsize j = 0; j < b64_alphabet_len; j++) {
            if (text[i] == b64_alphabet[j] || text[i] == '=' || text[i] == '\n') {
                found++;
                break;
            }
        }
    }
    return (found == data_len);
}


/* ---- Thread data structures ---- */

typedef struct {
    GtkcryptoTextCryptoPage *page;
    gchar *pwd;
    gchar *input_text;
    gchar *result_b64;
    gchar *error_msg;
} EncryptTextData;

typedef struct {
    GtkcryptoTextCryptoPage *page;
    gchar *pwd;
    guchar *encrypted_buf;
    gsize encrypted_len;
    gchar *result_plain;
    gchar *error_msg;
} DecryptTextData;


/* ---- Encrypt thread ---- */

static gpointer
encrypt_text_thread (gpointer user_data)
{
    EncryptTextData *d = user_data;
    const gchar *pwd = d->pwd;
    gchar *text = d->input_text;

    gint text_size = (gint)strlen (text) + 1;
    gint algo = gcry_cipher_map_name ("aes256");
    guint8 *iv = gcry_calloc (AES256_IV_SIZE, 1);
    guint8 *salt = gcry_calloc (KDF_SALT_SIZE, 1);
    guint8 *derived_key = gcry_calloc_secure (AES256_KEY_SIZE, 1);

    gcry_create_nonce (iv, AES256_IV_SIZE);
    gcry_create_nonce (salt, KDF_SALT_SIZE);

    gcry_cipher_hd_t hd;
    gcry_cipher_open (&hd, algo, GCRY_CIPHER_MODE_GCM, 0);

    gpg_error_t err = gcry_kdf_derive (pwd, g_utf8_strlen (pwd, -1) + 1,
                                        GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                                        salt, KDF_SALT_SIZE,
                                        KDF_ITERATIONS,
                                        AES256_KEY_SIZE, derived_key);
    if (err) {
        d->error_msg = g_strdup ("Key derivation failed");
        gcry_free (iv); gcry_free (salt); gcry_free (derived_key);
        gcry_cipher_close (hd);
        return NULL;
    }

    gcry_cipher_setkey (hd, derived_key, AES256_KEY_SIZE);
    gcry_cipher_setiv (hd, iv, AES256_IV_SIZE);

    guchar *enc_buf = gcry_calloc ((gsize)text_size, 1);
    err = gcry_cipher_encrypt (hd, enc_buf, (gsize)text_size, text, (gsize)text_size);

    if (err) {
        d->error_msg = g_strdup ("Encryption failed");
        gcry_free (iv); gcry_free (salt); gcry_free (derived_key); gcry_free (enc_buf);
        gcry_cipher_close (hd);
        return NULL;
    }

    gsize final_size = (gsize)text_size + TAG_SIZE + AES256_IV_SIZE + KDF_SALT_SIZE;
    guchar *final_buf = gcry_calloc (final_size, 1);
    memcpy (final_buf, iv, AES256_IV_SIZE);
    memcpy (final_buf + AES256_IV_SIZE, salt, KDF_SALT_SIZE);
    memcpy (final_buf + AES256_IV_SIZE + KDF_SALT_SIZE, enc_buf, (gsize)text_size);

    guint8 tag[TAG_SIZE];
    gcry_cipher_gettag (hd, tag, TAG_SIZE);
    gcry_cipher_close (hd);

    memcpy (final_buf + AES256_IV_SIZE + KDF_SALT_SIZE + text_size, tag, TAG_SIZE);

    d->result_b64 = g_base64_encode (final_buf, final_size);

    gcry_free (final_buf);
    gcry_free (enc_buf);
    gcry_free (derived_key);
    gcry_free (iv);
    gcry_free (salt);

    return NULL;
}


static gboolean
encrypt_text_done_idle (gpointer user_data)
{
    EncryptTextData *d = user_data;

    gtk_spinner_stop (d->page->enc_spinner);
    gtk_widget_set_sensitive (d->page->enc_btn, TRUE);

    if (d->error_msg) {
        show_toast (d->page->enc_toast_overlay, d->error_msg);
        g_free (d->error_msg);
    } else {
        gtk_text_buffer_set_text (d->page->enc_output_buf, d->result_b64, -1);
        show_toast (d->page->enc_toast_overlay, "Text encrypted successfully");
        g_free (d->result_b64);
    }

    gcry_free (d->pwd);
    g_free (d->input_text);
    g_free (d);
    return G_SOURCE_REMOVE;
}


static gpointer
encrypt_text_thread_wrapper (gpointer user_data)
{
    encrypt_text_thread (user_data);
    g_idle_add (encrypt_text_done_idle, user_data);
    return NULL;
}


static void
encrypt_text_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoTextCryptoPage *self = user_data;

    const gchar *pwd = gtk_editable_get_text (GTK_EDITABLE (self->enc_pwd_row));
    const gchar *pwd_confirm = gtk_editable_get_text (GTK_EDITABLE (self->enc_pwd_confirm_row));

    if (g_utf8_strlen (pwd, -1) < 8) {
        show_toast (self->enc_toast_overlay, "Password must be at least 8 characters");
        return;
    }
    if (g_strcmp0 (pwd, pwd_confirm) != 0) {
        show_toast (self->enc_toast_overlay, "Passwords do not match");
        return;
    }

    gchar *text = get_buffer_text (self->enc_input_buf);
    if (!text || *text == '\0') {
        show_toast (self->enc_toast_overlay, "No input text");
        g_free (text);
        return;
    }

    gint text_size = (gint)strlen (text) + 1;
    if (text_size > 32768) {
        show_toast (self->enc_toast_overlay, "Input text too large");
        g_free (text);
        return;
    }

    if (!g_utf8_validate (text, -1, NULL)) {
        show_toast (self->enc_toast_overlay, "Input is not valid UTF-8");
        g_free (text);
        return;
    }

    gtk_widget_set_sensitive (self->enc_btn, FALSE);
    gtk_spinner_start (self->enc_spinner);

    EncryptTextData *d = g_new0 (EncryptTextData, 1);
    d->page = self;
    gsize pwd_len = strlen (pwd) + 1;
    d->pwd = gcry_malloc_secure (pwd_len);
    memcpy (d->pwd, pwd, pwd_len);
    d->input_text = text;

    g_thread_new ("text-encrypt", encrypt_text_thread_wrapper, d);
}


/* ---- Decrypt thread ---- */

static gpointer
decrypt_text_thread (gpointer user_data)
{
    DecryptTextData *d = user_data;
    const gchar *pwd = d->pwd;
    guchar *encrypted_buf = d->encrypted_buf;
    gsize out_len = d->encrypted_len;

    guint8 *iv = gcry_calloc (AES256_IV_SIZE, 1);
    guint8 *salt = gcry_calloc (KDF_SALT_SIZE, 1);
    guint8 *derived_key = gcry_calloc_secure (AES256_KEY_SIZE, 1);

    memcpy (iv, encrypted_buf, AES256_IV_SIZE);
    memcpy (salt, encrypted_buf + AES256_IV_SIZE, KDF_SALT_SIZE);

    gint algo = gcry_cipher_map_name ("aes256");
    gcry_cipher_hd_t hd;
    gcry_cipher_open (&hd, algo, GCRY_CIPHER_MODE_GCM, 0);

    gpg_error_t err = gcry_kdf_derive (pwd, g_utf8_strlen (pwd, -1) + 1,
                                        GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                                        salt, KDF_SALT_SIZE,
                                        KDF_ITERATIONS,
                                        AES256_KEY_SIZE, derived_key);
    if (err) {
        d->error_msg = g_strdup ("Key derivation failed");
        gcry_free (iv); gcry_free (salt); gcry_free (derived_key);
        gcry_cipher_close (hd);
        return NULL;
    }

    gcry_cipher_setkey (hd, derived_key, AES256_KEY_SIZE);
    gcry_cipher_setiv (hd, iv, AES256_IV_SIZE);

    gsize enc_body_len = out_len - AES256_IV_SIZE - KDF_SALT_SIZE - TAG_SIZE;
    guchar *enc_body = g_malloc0 (enc_body_len);
    memcpy (enc_body, encrypted_buf + AES256_IV_SIZE + KDF_SALT_SIZE, enc_body_len);

    gchar *plain_buf = gcry_calloc_secure (enc_body_len, 1);
    gcry_cipher_decrypt (hd, plain_buf, enc_body_len, enc_body, enc_body_len);

    guint8 tag[TAG_SIZE];
    memcpy (tag, encrypted_buf + (out_len - TAG_SIZE), TAG_SIZE);
    err = gcry_cipher_checktag (hd, tag, TAG_SIZE);
    gcry_cipher_close (hd);

    if (err) {
        d->error_msg = g_strdup ("Wrong password or corrupted data");
        gcry_free (iv); gcry_free (salt); gcry_free (derived_key);
        gcry_free (plain_buf);
        g_free (enc_body);
        return NULL;
    }

    d->result_plain = g_strdup (plain_buf);

    gcry_free (plain_buf);
    gcry_free (iv);
    gcry_free (salt);
    gcry_free (derived_key);
    g_free (enc_body);

    return NULL;
}


static gboolean
decrypt_text_done_idle (gpointer user_data)
{
    DecryptTextData *d = user_data;

    gtk_spinner_stop (d->page->dec_spinner);
    gtk_widget_set_sensitive (d->page->dec_btn, TRUE);

    if (d->error_msg) {
        show_toast (d->page->dec_toast_overlay, d->error_msg);
        g_free (d->error_msg);
    } else {
        gtk_text_buffer_set_text (d->page->dec_output_buf, d->result_plain, -1);
        show_toast (d->page->dec_toast_overlay, "Text decrypted successfully");
        g_free (d->result_plain);
    }

    gcry_free (d->pwd);
    g_free (d->encrypted_buf);
    g_free (d);
    return G_SOURCE_REMOVE;
}


static gpointer
decrypt_text_thread_wrapper (gpointer user_data)
{
    decrypt_text_thread (user_data);
    g_idle_add (decrypt_text_done_idle, user_data);
    return NULL;
}


static void
decrypt_text_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoTextCryptoPage *self = user_data;

    const gchar *pwd = gtk_editable_get_text (GTK_EDITABLE (self->dec_pwd_row));
    if (g_utf8_strlen (pwd, -1) < 8) {
        show_toast (self->dec_toast_overlay, "Password must be at least 8 characters");
        return;
    }

    gchar *text = get_buffer_text (self->dec_input_buf);
    if (!text || *text == '\0') {
        show_toast (self->dec_toast_overlay, "No input text");
        g_free (text);
        return;
    }

    if (!g_str_is_ascii (text)) {
        show_toast (self->dec_toast_overlay, "Input contains invalid characters (only ASCII allowed)");
        g_free (text);
        return;
    }

    if (!is_b64_encoded (text)) {
        show_toast (self->dec_toast_overlay, "Input is not valid base64");
        g_free (text);
        return;
    }

    gsize out_len = 0;
    guchar *encrypted_buf = g_base64_decode (text, &out_len);
    g_free (text);

    if (out_len < AES256_IV_SIZE + KDF_SALT_SIZE + TAG_SIZE + 1) {
        show_toast (self->dec_toast_overlay, "Input data is too short");
        g_free (encrypted_buf);
        return;
    }

    gtk_widget_set_sensitive (self->dec_btn, FALSE);
    gtk_spinner_start (self->dec_spinner);

    DecryptTextData *d = g_new0 (DecryptTextData, 1);
    d->page = self;
    gsize pwd_len = strlen (pwd) + 1;
    d->pwd = gcry_malloc_secure (pwd_len);
    memcpy (d->pwd, pwd, pwd_len);
    d->encrypted_buf = encrypted_buf;
    d->encrypted_len = out_len;

    g_thread_new ("text-decrypt", decrypt_text_thread_wrapper, d);
}


static void
copy_output_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkTextBuffer *buf = GTK_TEXT_BUFFER (user_data);
    gchar *text = get_buffer_text (buf);
    if (text && *text) {
        GdkClipboard *clipboard = gdk_display_get_clipboard (gdk_display_get_default ());
        gdk_clipboard_set_text (clipboard, text);
    }
    g_free (text);
}


static GtkWidget *
create_text_view_with_scroll (GtkTextBuffer **buf_out)
{
    *buf_out = gtk_text_buffer_new (NULL);
    GtkWidget *view = gtk_text_view_new_with_buffer (*buf_out);
    gtk_text_view_set_wrap_mode (GTK_TEXT_VIEW (view), GTK_WRAP_CHAR);
    gtk_widget_add_css_class (view, "text-crypto-view");
    gtk_widget_set_vexpand (view, TRUE);

    GtkWidget *frame = gtk_frame_new (NULL);
    GtkWidget *scroll = gtk_scrolled_window_new ();
    gtk_scrolled_window_set_min_content_height (GTK_SCROLLED_WINDOW (scroll), 120);
    gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scroll), view);
    gtk_frame_set_child (GTK_FRAME (frame), scroll);

    return frame;
}


static GtkWidget *
build_text_encrypt_page (GtkcryptoTextCryptoPage *self)
{
    self->enc_toast_overlay = ADW_TOAST_OVERLAY (adw_toast_overlay_new ());

    GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top (page, 24);
    gtk_widget_set_margin_bottom (page, 24);
    gtk_widget_set_margin_start (page, 24);
    gtk_widget_set_margin_end (page, 24);

    GtkWidget *clamp = adw_clamp_new ();
    adw_clamp_set_maximum_size (ADW_CLAMP (clamp), 700);
    gtk_widget_set_vexpand (clamp, TRUE);

    GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);

    /* Input */
    GtkWidget *input_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (input_group), "Input Text");
    GtkWidget *input_frame = create_text_view_with_scroll (&self->enc_input_buf);
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (input_group), input_frame);

    /* Password */
    GtkWidget *pwd_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (pwd_group), "Password");
    self->enc_pwd_row = ADW_PASSWORD_ENTRY_ROW (adw_password_entry_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->enc_pwd_row), "Password");
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (pwd_group), GTK_WIDGET (self->enc_pwd_row));
    self->enc_pwd_confirm_row = ADW_PASSWORD_ENTRY_ROW (adw_password_entry_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->enc_pwd_confirm_row), "Confirm Password");
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (pwd_group), GTK_WIDGET (self->enc_pwd_confirm_row));

    /* Encrypt button + spinner */
    GtkWidget *action_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign (action_box, GTK_ALIGN_CENTER);
    self->enc_btn = gtk_button_new ();
    GtkWidget *enc_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append (GTK_BOX (enc_box), gtk_image_new_from_icon_name ("channel-secure-symbolic"));
    gtk_box_append (GTK_BOX (enc_box), gtk_label_new ("Encrypt"));
    gtk_button_set_child (GTK_BUTTON (self->enc_btn), enc_box);
    gtk_widget_add_css_class (self->enc_btn, "suggested-action");
    gtk_widget_add_css_class (self->enc_btn, "pill");
    self->enc_spinner = GTK_SPINNER (gtk_spinner_new ());
    gtk_box_append (GTK_BOX (action_box), self->enc_btn);
    gtk_box_append (GTK_BOX (action_box), GTK_WIDGET (self->enc_spinner));
    g_signal_connect (self->enc_btn, "clicked", G_CALLBACK (encrypt_text_clicked_cb), self);

    /* Output */
    GtkWidget *output_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (output_group), "Encrypted Output");
    GtkWidget *output_frame = create_text_view_with_scroll (&self->enc_output_buf);
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (output_group), output_frame);

    GtkWidget *copy_btn = gtk_button_new_with_label ("Copy Output");
    gtk_widget_add_css_class (copy_btn, "flat");
    gtk_widget_set_halign (copy_btn, GTK_ALIGN_CENTER);
    g_signal_connect (copy_btn, "clicked", G_CALLBACK (copy_output_clicked_cb), self->enc_output_buf);

    gtk_box_append (GTK_BOX (inner), input_group);
    gtk_box_append (GTK_BOX (inner), pwd_group);
    gtk_box_append (GTK_BOX (inner), action_box);
    gtk_box_append (GTK_BOX (inner), output_group);
    gtk_box_append (GTK_BOX (inner), copy_btn);

    adw_clamp_set_child (ADW_CLAMP (clamp), inner);
    gtk_box_append (GTK_BOX (page), clamp);

    adw_toast_overlay_set_child (self->enc_toast_overlay, page);
    return GTK_WIDGET (self->enc_toast_overlay);
}


static GtkWidget *
build_text_decrypt_page (GtkcryptoTextCryptoPage *self)
{
    self->dec_toast_overlay = ADW_TOAST_OVERLAY (adw_toast_overlay_new ());

    GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top (page, 24);
    gtk_widget_set_margin_bottom (page, 24);
    gtk_widget_set_margin_start (page, 24);
    gtk_widget_set_margin_end (page, 24);

    GtkWidget *clamp = adw_clamp_new ();
    adw_clamp_set_maximum_size (ADW_CLAMP (clamp), 700);
    gtk_widget_set_vexpand (clamp, TRUE);

    GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);

    /* Input */
    GtkWidget *input_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (input_group), "Encrypted Input (Base64)");
    GtkWidget *input_frame = create_text_view_with_scroll (&self->dec_input_buf);
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (input_group), input_frame);

    /* Password */
    GtkWidget *pwd_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (pwd_group), "Password");
    self->dec_pwd_row = ADW_PASSWORD_ENTRY_ROW (adw_password_entry_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->dec_pwd_row), "Password");
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (pwd_group), GTK_WIDGET (self->dec_pwd_row));

    /* Decrypt button + spinner */
    GtkWidget *action_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign (action_box, GTK_ALIGN_CENTER);
    self->dec_btn = gtk_button_new ();
    GtkWidget *dec_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append (GTK_BOX (dec_box), gtk_image_new_from_icon_name ("channel-insecure-symbolic"));
    gtk_box_append (GTK_BOX (dec_box), gtk_label_new ("Decrypt"));
    gtk_button_set_child (GTK_BUTTON (self->dec_btn), dec_box);
    gtk_widget_add_css_class (self->dec_btn, "suggested-action");
    gtk_widget_add_css_class (self->dec_btn, "pill");
    self->dec_spinner = GTK_SPINNER (gtk_spinner_new ());
    gtk_box_append (GTK_BOX (action_box), self->dec_btn);
    gtk_box_append (GTK_BOX (action_box), GTK_WIDGET (self->dec_spinner));
    g_signal_connect (self->dec_btn, "clicked", G_CALLBACK (decrypt_text_clicked_cb), self);

    /* Output */
    GtkWidget *output_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (output_group), "Decrypted Output");
    GtkWidget *output_frame = create_text_view_with_scroll (&self->dec_output_buf);
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (output_group), output_frame);

    GtkWidget *copy_btn = gtk_button_new_with_label ("Copy Output");
    gtk_widget_add_css_class (copy_btn, "flat");
    gtk_widget_set_halign (copy_btn, GTK_ALIGN_CENTER);
    g_signal_connect (copy_btn, "clicked", G_CALLBACK (copy_output_clicked_cb), self->dec_output_buf);

    gtk_box_append (GTK_BOX (inner), input_group);
    gtk_box_append (GTK_BOX (inner), pwd_group);
    gtk_box_append (GTK_BOX (inner), action_box);
    gtk_box_append (GTK_BOX (inner), output_group);
    gtk_box_append (GTK_BOX (inner), copy_btn);

    adw_clamp_set_child (ADW_CLAMP (clamp), inner);
    gtk_box_append (GTK_BOX (page), clamp);

    adw_toast_overlay_set_child (self->dec_toast_overlay, page);
    return GTK_WIDGET (self->dec_toast_overlay);
}


static void
gtkcrypto_text_crypto_page_finalize (GObject *object)
{
    GtkcryptoTextCryptoPage *self = GTKCRYPTO_TEXT_CRYPTO_PAGE (object);

    g_clear_object (&self->enc_input_buf);
    g_clear_object (&self->enc_output_buf);
    g_clear_object (&self->dec_input_buf);
    g_clear_object (&self->dec_output_buf);

    G_OBJECT_CLASS (gtkcrypto_text_crypto_page_parent_class)->finalize (object);
}


static void
gtkcrypto_text_crypto_page_init (GtkcryptoTextCryptoPage *self)
{
    gtk_orientable_set_orientation (GTK_ORIENTABLE (self), GTK_ORIENTATION_VERTICAL);

    self->view_stack = ADW_VIEW_STACK (adw_view_stack_new ());

    GtkWidget *switcher = adw_view_switcher_new ();
    adw_view_switcher_set_stack (ADW_VIEW_SWITCHER (switcher), self->view_stack);
    adw_view_switcher_set_policy (ADW_VIEW_SWITCHER (switcher), ADW_VIEW_SWITCHER_POLICY_WIDE);
    gtk_widget_set_halign (switcher, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top (switcher, 8);

    GtkWidget *enc_page = build_text_encrypt_page (self);
    AdwViewStackPage *enc_vs_page = adw_view_stack_add_titled (self->view_stack, enc_page, "encrypt", "Encrypt");
    adw_view_stack_page_set_icon_name (enc_vs_page, "channel-secure-symbolic");

    GtkWidget *dec_page = build_text_decrypt_page (self);
    AdwViewStackPage *dec_vs_page = adw_view_stack_add_titled (self->view_stack, dec_page, "decrypt", "Decrypt");
    adw_view_stack_page_set_icon_name (dec_vs_page, "channel-insecure-symbolic");

    gtk_box_append (GTK_BOX (self), switcher);
    gtk_box_append (GTK_BOX (self), GTK_WIDGET (self->view_stack));
    gtk_widget_set_vexpand (GTK_WIDGET (self->view_stack), TRUE);
}


static void
gtkcrypto_text_crypto_page_class_init (GtkcryptoTextCryptoPageClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    object_class->finalize = gtkcrypto_text_crypto_page_finalize;
}


GtkcryptoTextCryptoPage *
gtkcrypto_text_crypto_page_new (void)
{
    return g_object_new (GTKCRYPTO_TYPE_TEXT_CRYPTO_PAGE, NULL);
}
