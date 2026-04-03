#include <gcrypt.h>
#include <glib/gstdio.h>
#include "file-crypto-page.h"
#include "../encrypt-files-cb.h"
#include "../decrypt-files-cb.h"
#include "../hash.h"
#include "../crypt-common.h"
#include "../cleanup.h"

static const gchar *cipher_labels[] = { "AES-256", "Twofish", "Serpent", "Camellia", NULL };
static const gint cipher_algos[] = { GCRY_CIPHER_AES256, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_SERPENT256, GCRY_CIPHER_CAMELLIA256 };
static const gchar *mode_labels[] = { "CTR", "CBC", NULL };
static const gint mode_algos[] = { GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_MODE_CBC };

struct _GtkcryptoFileCryptoPage {
    GtkBox parent_instance;

    AdwViewStack *view_stack;

    /* Encrypt sub-page */
    GtkLabel      *enc_file_label;
    GSList        *enc_files_list;
    AdwComboRow   *cipher_row;
    AdwComboRow   *mode_row;
    AdwPasswordEntryRow *enc_pwd_row;
    AdwPasswordEntryRow *enc_pwd_confirm_row;
    GtkWidget     *encrypt_btn;
    GtkSpinner    *enc_spinner;
    AdwToastOverlay *enc_toast_overlay;

    /* Decrypt sub-page */
    GtkLabel      *dec_file_label;
    GSList        *dec_files_list;
    AdwPasswordEntryRow *dec_pwd_row;
    GtkSwitch     *delete_switch;
    GtkWidget     *decrypt_btn;
    GtkSpinner    *dec_spinner;
    AdwToastOverlay *dec_toast_overlay;
};

G_DEFINE_TYPE (GtkcryptoFileCryptoPage, gtkcrypto_file_crypto_page, GTK_TYPE_BOX)

typedef struct {
    GtkcryptoFileCryptoPage *page;
    GMutex                   mutex;
    guint                    running;
    guint                    failed;
    guint                    total;
    gchar                   *pwd;
    gint                     algo;
    gint                     mode;
    gboolean                 first_run;
    GThreadPool             *pool;
    guint                    source_id;
    gboolean                 is_encrypt;
    gboolean                 delete_file;
} CryptoJobData;


static const gchar *
get_algo_name_for_encrypt (gint algo)
{
    switch (algo) {
        case GCRY_CIPHER_AES256:       return "aes_rbtn_widget";
        case GCRY_CIPHER_TWOFISH:      return "twofish_rbtn_widget";
        case GCRY_CIPHER_SERPENT256:    return "serpent_rbtn_widget";
        case GCRY_CIPHER_CAMELLIA256:   return "camellia_rbtn_widget";
        default: return "aes_rbtn_widget";
    }
}

static const gchar *
get_mode_name_for_encrypt (gint mode)
{
    return (mode == GCRY_CIPHER_MODE_CBC) ? "cbc_rbtn_widget" : "ctr_rbtn_widget";
}


static void
enc_exec_thread (gpointer data, gpointer user_data)
{
    const gchar *filename = data;
    CryptoJobData *job = user_data;

    g_mutex_lock (&job->mutex);
    job->running++;
    g_mutex_unlock (&job->mutex);

    gpointer ret = encrypt_file (filename, job->pwd,
                                  get_algo_name_for_encrypt (job->algo),
                                  get_mode_name_for_encrypt (job->mode));
    if (ret != NULL) {
        g_mutex_lock (&job->mutex);
        job->failed++;
        g_mutex_unlock (&job->mutex);
        g_free (ret);
    }

    g_mutex_lock (&job->mutex);
    job->running--;
    job->first_run = FALSE;
    g_mutex_unlock (&job->mutex);
}


static void
dec_exec_thread (gpointer data, gpointer user_data)
{
    const gchar *filename = data;
    CryptoJobData *job = user_data;

    g_mutex_lock (&job->mutex);
    job->running++;
    g_mutex_unlock (&job->mutex);

    gpointer ret = decrypt_file (filename, job->pwd);
    if (ret != NULL) {
        g_mutex_lock (&job->mutex);
        job->failed++;
        g_mutex_unlock (&job->mutex);
        g_free (ret);
    } else if (job->delete_file) {
        g_unlink (filename);
    }

    g_mutex_lock (&job->mutex);
    job->running--;
    job->first_run = FALSE;
    g_mutex_unlock (&job->mutex);
}


typedef struct {
    GtkSpinner      *spinner;
    AdwToastOverlay *overlay;
    gchar           *message;
} JobDoneData;


static gboolean
job_done_idle (gpointer user_data)
{
    JobDoneData *d = user_data;
    gtk_spinner_stop (d->spinner);
    adw_toast_overlay_add_toast (d->overlay, adw_toast_new (d->message));
    g_free (d->message);
    g_free (d);
    return G_SOURCE_REMOVE;
}


static gboolean
check_job_done (gpointer user_data)
{
    CryptoJobData *job = user_data;

    if (job->running == 0 && !job->first_run) {
        g_thread_pool_free (job->pool, FALSE, TRUE);

        JobDoneData *d = g_new0 (JobDoneData, 1);
        d->message = g_strdup_printf ("%u/%u file(s) successfully %s.",
                                       job->total - job->failed, job->total,
                                       job->is_encrypt ? "encrypted" : "decrypted");

        if (job->is_encrypt) {
            d->spinner = job->page->enc_spinner;
            d->overlay = job->page->enc_toast_overlay;
            gtk_widget_set_sensitive (job->page->encrypt_btn, TRUE);
        } else {
            d->spinner = job->page->dec_spinner;
            d->overlay = job->page->dec_toast_overlay;
            gtk_widget_set_sensitive (job->page->decrypt_btn, TRUE);
        }
        g_idle_add (job_done_idle, d);

        g_free (job->pwd);
        g_free (job);
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}


/* ---- File chooser ---- */

static void
enc_files_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoFileCryptoPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GListModel) files = gtk_file_dialog_open_multiple_finish (dialog, result, NULL);
    if (files == NULL) return;

    g_slist_free_full (self->enc_files_list, g_free);
    self->enc_files_list = NULL;

    guint n = g_list_model_get_n_items (files);
    for (guint i = 0; i < n; i++) {
        g_autoptr(GFile) f = g_list_model_get_item (files, i);
        self->enc_files_list = g_slist_append (self->enc_files_list, g_file_get_path (f));
    }

    gchar *label = g_strdup_printf ("%u file(s) selected", n);
    gtk_label_set_text (self->enc_file_label, label);
    g_free (label);
}

static void
enc_choose_files_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoFileCryptoPage *self = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, "Choose file(s) to encrypt");
    GtkWidget *toplevel = GTK_WIDGET (gtk_widget_get_root (GTK_WIDGET (self)));
    gtk_file_dialog_open_multiple (dialog, GTK_WINDOW (toplevel), NULL,
                                   enc_files_chosen_cb, self);
}


static void
dec_files_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoFileCryptoPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GListModel) files = gtk_file_dialog_open_multiple_finish (dialog, result, NULL);
    if (files == NULL) return;

    g_slist_free_full (self->dec_files_list, g_free);
    self->dec_files_list = NULL;

    guint n = g_list_model_get_n_items (files);
    for (guint i = 0; i < n; i++) {
        g_autoptr(GFile) f = g_list_model_get_item (files, i);
        self->dec_files_list = g_slist_append (self->dec_files_list, g_file_get_path (f));
    }

    gchar *label = g_strdup_printf ("%u file(s) selected", n);
    gtk_label_set_text (self->dec_file_label, label);
    g_free (label);
}

static void
dec_choose_files_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoFileCryptoPage *self = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, "Choose file(s) to decrypt");
    GtkWidget *toplevel = GTK_WIDGET (gtk_widget_get_root (GTK_WIDGET (self)));
    gtk_file_dialog_open_multiple (dialog, GTK_WINDOW (toplevel), NULL,
                                   dec_files_chosen_cb, self);
}


/* ---- Encrypt/Decrypt actions ---- */

static void
show_toast (AdwToastOverlay *overlay, const gchar *msg)
{
    adw_toast_overlay_add_toast (overlay, adw_toast_new (msg));
}


static void
encrypt_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoFileCryptoPage *self = user_data;

    if (self->enc_files_list == NULL) {
        show_toast (self->enc_toast_overlay, "No files selected");
        return;
    }

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

    guint selected_cipher = adw_combo_row_get_selected (self->cipher_row);
    guint selected_mode = adw_combo_row_get_selected (self->mode_row);

    CryptoJobData *job = g_new0 (CryptoJobData, 1);
    job->page = self;
    job->pwd = g_strdup (pwd);
    job->algo = cipher_algos[selected_cipher];
    job->mode = mode_algos[selected_mode];
    job->total = g_slist_length (self->enc_files_list);
    job->first_run = TRUE;
    job->is_encrypt = TRUE;
    g_mutex_init (&job->mutex);

    gtk_widget_set_sensitive (self->encrypt_btn, FALSE);
    gtk_spinner_start (self->enc_spinner);

    job->pool = g_thread_pool_new (enc_exec_thread, job,
                                    (gint)g_get_num_processors (), TRUE, NULL);
    for (GSList *l = self->enc_files_list; l; l = l->next) {
        g_thread_pool_push (job->pool, l->data, NULL);
    }

    job->source_id = g_timeout_add (500, check_job_done, job);
}


static void
decrypt_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoFileCryptoPage *self = user_data;

    if (self->dec_files_list == NULL) {
        show_toast (self->dec_toast_overlay, "No files selected");
        return;
    }

    const gchar *pwd = gtk_editable_get_text (GTK_EDITABLE (self->dec_pwd_row));
    if (g_utf8_strlen (pwd, -1) < 8) {
        show_toast (self->dec_toast_overlay, "Password must be at least 8 characters");
        return;
    }

    CryptoJobData *job = g_new0 (CryptoJobData, 1);
    job->page = self;
    job->pwd = g_strdup (pwd);
    job->total = g_slist_length (self->dec_files_list);
    job->first_run = TRUE;
    job->is_encrypt = FALSE;
    job->delete_file = gtk_switch_get_active (self->delete_switch);
    g_mutex_init (&job->mutex);

    gtk_widget_set_sensitive (self->decrypt_btn, FALSE);
    gtk_spinner_start (self->dec_spinner);

    job->pool = g_thread_pool_new (dec_exec_thread, job,
                                    (gint)g_get_num_processors (), TRUE, NULL);
    for (GSList *l = self->dec_files_list; l; l = l->next) {
        g_thread_pool_push (job->pool, l->data, NULL);
    }

    job->source_id = g_timeout_add (500, check_job_done, job);
}


/* ---- Build UI ---- */

static GtkWidget *
build_encrypt_page (GtkcryptoFileCryptoPage *self)
{
    self->enc_toast_overlay = ADW_TOAST_OVERLAY (adw_toast_overlay_new ());

    GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top (page, 24);
    gtk_widget_set_margin_bottom (page, 24);
    gtk_widget_set_margin_start (page, 24);
    gtk_widget_set_margin_end (page, 24);

    GtkWidget *clamp = adw_clamp_new ();
    adw_clamp_set_maximum_size (ADW_CLAMP (clamp), 600);
    gtk_widget_set_vexpand (clamp, TRUE);

    GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 16);

    /* File chooser */
    GtkWidget *file_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (file_group), "Files");
    GtkWidget *file_row = adw_action_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (file_row), "Files to encrypt");
    self->enc_file_label = GTK_LABEL (gtk_label_new ("No files selected"));
    gtk_label_set_ellipsize (self->enc_file_label, PANGO_ELLIPSIZE_END);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file_row), GTK_WIDGET (self->enc_file_label));
    GtkWidget *file_btn = gtk_button_new_from_icon_name ("document-open-symbolic");
    gtk_widget_set_valign (file_btn, GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file_row), file_btn);
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (file_group), file_row);
    g_signal_connect (file_btn, "clicked", G_CALLBACK (enc_choose_files_cb), self);

    /* Cipher and mode */
    GtkWidget *crypto_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (crypto_group), "Encryption Settings");

    self->cipher_row = ADW_COMBO_ROW (adw_combo_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->cipher_row), "Cipher");
    adw_combo_row_set_model (self->cipher_row, G_LIST_MODEL (gtk_string_list_new (cipher_labels)));
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (crypto_group), GTK_WIDGET (self->cipher_row));

    self->mode_row = ADW_COMBO_ROW (adw_combo_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->mode_row), "Mode");
    adw_combo_row_set_model (self->mode_row, G_LIST_MODEL (gtk_string_list_new (mode_labels)));
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (crypto_group), GTK_WIDGET (self->mode_row));

    /* Password */
    GtkWidget *pwd_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (pwd_group), "Password");

    self->enc_pwd_row = ADW_PASSWORD_ENTRY_ROW (adw_password_entry_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->enc_pwd_row), "Password");
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (pwd_group), GTK_WIDGET (self->enc_pwd_row));

    self->enc_pwd_confirm_row = ADW_PASSWORD_ENTRY_ROW (adw_password_entry_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->enc_pwd_confirm_row), "Confirm Password");
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (pwd_group), GTK_WIDGET (self->enc_pwd_confirm_row));

    /* Encrypt button */
    GtkWidget *action_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign (action_box, GTK_ALIGN_CENTER);
    self->encrypt_btn = gtk_button_new_with_label ("Encrypt");
    gtk_widget_add_css_class (self->encrypt_btn, "suggested-action");
    gtk_widget_add_css_class (self->encrypt_btn, "pill");
    self->enc_spinner = GTK_SPINNER (gtk_spinner_new ());
    gtk_box_append (GTK_BOX (action_box), self->encrypt_btn);
    gtk_box_append (GTK_BOX (action_box), GTK_WIDGET (self->enc_spinner));
    g_signal_connect (self->encrypt_btn, "clicked", G_CALLBACK (encrypt_clicked_cb), self);

    gtk_box_append (GTK_BOX (inner), file_group);
    gtk_box_append (GTK_BOX (inner), crypto_group);
    gtk_box_append (GTK_BOX (inner), pwd_group);
    gtk_box_append (GTK_BOX (inner), action_box);

    adw_clamp_set_child (ADW_CLAMP (clamp), inner);
    gtk_box_append (GTK_BOX (page), clamp);

    adw_toast_overlay_set_child (self->enc_toast_overlay, page);
    return GTK_WIDGET (self->enc_toast_overlay);
}


static GtkWidget *
build_decrypt_page (GtkcryptoFileCryptoPage *self)
{
    self->dec_toast_overlay = ADW_TOAST_OVERLAY (adw_toast_overlay_new ());

    GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top (page, 24);
    gtk_widget_set_margin_bottom (page, 24);
    gtk_widget_set_margin_start (page, 24);
    gtk_widget_set_margin_end (page, 24);

    GtkWidget *clamp = adw_clamp_new ();
    adw_clamp_set_maximum_size (ADW_CLAMP (clamp), 600);
    gtk_widget_set_vexpand (clamp, TRUE);

    GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 16);

    /* File chooser */
    GtkWidget *file_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (file_group), "Files");
    GtkWidget *file_row = adw_action_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (file_row), "Files to decrypt");
    self->dec_file_label = GTK_LABEL (gtk_label_new ("No files selected"));
    gtk_label_set_ellipsize (self->dec_file_label, PANGO_ELLIPSIZE_END);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file_row), GTK_WIDGET (self->dec_file_label));
    GtkWidget *file_btn = gtk_button_new_from_icon_name ("document-open-symbolic");
    gtk_widget_set_valign (file_btn, GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file_row), file_btn);
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (file_group), file_row);
    g_signal_connect (file_btn, "clicked", G_CALLBACK (dec_choose_files_cb), self);

    /* Password */
    GtkWidget *pwd_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (pwd_group), "Password");
    self->dec_pwd_row = ADW_PASSWORD_ENTRY_ROW (adw_password_entry_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->dec_pwd_row), "Password");
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (pwd_group), GTK_WIDGET (self->dec_pwd_row));

    /* Options */
    GtkWidget *opts_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (opts_group), "Options");
    GtkWidget *delete_row = adw_action_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (delete_row), "Delete encrypted file after decryption");
    self->delete_switch = GTK_SWITCH (gtk_switch_new ());
    gtk_widget_set_valign (GTK_WIDGET (self->delete_switch), GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (delete_row), GTK_WIDGET (self->delete_switch));
    adw_action_row_set_activatable_widget (ADW_ACTION_ROW (delete_row), GTK_WIDGET (self->delete_switch));
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (opts_group), delete_row);

    /* Decrypt button */
    GtkWidget *action_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign (action_box, GTK_ALIGN_CENTER);
    self->decrypt_btn = gtk_button_new_with_label ("Decrypt");
    gtk_widget_add_css_class (self->decrypt_btn, "suggested-action");
    gtk_widget_add_css_class (self->decrypt_btn, "pill");
    self->dec_spinner = GTK_SPINNER (gtk_spinner_new ());
    gtk_box_append (GTK_BOX (action_box), self->decrypt_btn);
    gtk_box_append (GTK_BOX (action_box), GTK_WIDGET (self->dec_spinner));
    g_signal_connect (self->decrypt_btn, "clicked", G_CALLBACK (decrypt_clicked_cb), self);

    gtk_box_append (GTK_BOX (inner), file_group);
    gtk_box_append (GTK_BOX (inner), pwd_group);
    gtk_box_append (GTK_BOX (inner), opts_group);
    gtk_box_append (GTK_BOX (inner), action_box);

    adw_clamp_set_child (ADW_CLAMP (clamp), inner);
    gtk_box_append (GTK_BOX (page), clamp);

    adw_toast_overlay_set_child (self->dec_toast_overlay, page);
    return GTK_WIDGET (self->dec_toast_overlay);
}


static void
gtkcrypto_file_crypto_page_finalize (GObject *object)
{
    GtkcryptoFileCryptoPage *self = GTKCRYPTO_FILE_CRYPTO_PAGE (object);
    g_slist_free_full (self->enc_files_list, g_free);
    g_slist_free_full (self->dec_files_list, g_free);
    G_OBJECT_CLASS (gtkcrypto_file_crypto_page_parent_class)->finalize (object);
}


static void
gtkcrypto_file_crypto_page_init (GtkcryptoFileCryptoPage *self)
{
    gtk_orientable_set_orientation (GTK_ORIENTABLE (self), GTK_ORIENTATION_VERTICAL);

    self->view_stack = ADW_VIEW_STACK (adw_view_stack_new ());

    GtkWidget *switcher = adw_view_switcher_new ();
    adw_view_switcher_set_stack (ADW_VIEW_SWITCHER (switcher), self->view_stack);
    adw_view_switcher_set_policy (ADW_VIEW_SWITCHER (switcher), ADW_VIEW_SWITCHER_POLICY_WIDE);
    gtk_widget_set_halign (switcher, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top (switcher, 8);

    GtkWidget *enc_page = build_encrypt_page (self);
    adw_view_stack_add_titled (self->view_stack, enc_page, "encrypt", "Encrypt");

    GtkWidget *dec_page = build_decrypt_page (self);
    adw_view_stack_add_titled (self->view_stack, dec_page, "decrypt", "Decrypt");

    gtk_box_append (GTK_BOX (self), switcher);
    gtk_box_append (GTK_BOX (self), GTK_WIDGET (self->view_stack));
    gtk_widget_set_vexpand (GTK_WIDGET (self->view_stack), TRUE);
}


static void
gtkcrypto_file_crypto_page_class_init (GtkcryptoFileCryptoPageClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    object_class->finalize = gtkcrypto_file_crypto_page_finalize;
}


GtkcryptoFileCryptoPage *
gtkcrypto_file_crypto_page_new (void)
{
    return g_object_new (GTKCRYPTO_TYPE_FILE_CRYPTO_PAGE, NULL);
}
