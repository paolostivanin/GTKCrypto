#include <gcrypt.h>
#include <glib/gstdio.h>
#include <string.h>
#include "file-crypto-page.h"
#include "../encrypt-files-cb.h"
#include "../decrypt-files-cb.h"
#include "../hash.h"
#include "../crypt-common.h"

struct _GtkcryptoFileCryptoPage {
    GtkBox parent_instance;

    AdwViewStack *view_stack;

    /* Encrypt sub-page */
    GtkLabel      *enc_file_label;
    GSList        *enc_files_list;
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
    gboolean                 first_run;
    GThreadPool             *pool;
    guint                    source_id;
    gboolean                 is_encrypt;
    gboolean                 delete_file;
    gboolean                 overwrite;
} CryptoJobData;

static void start_encrypt_job (GtkcryptoFileCryptoPage *self,
                               gboolean overwrite);
static void start_decrypt_job (GtkcryptoFileCryptoPage *self,
                               gboolean overwrite);


static void
enc_exec_thread (gpointer data, gpointer user_data)
{
    gchar *filename = data;
    CryptoJobData *job = user_data;

    g_mutex_lock (&job->mutex);
    job->running++;
    g_mutex_unlock (&job->mutex);

    g_autofree gchar *output = g_strconcat (filename, ".enc", NULL);
    GError *error = NULL;
    gboolean ok = gtkcrypto_encrypt_file (
        filename, output, (const guint8 *)job->pwd, strlen (job->pwd),
        job->overwrite, NULL, &error);
    if (!ok) {
        g_mutex_lock (&job->mutex);
        job->failed++;
        g_mutex_unlock (&job->mutex);
        g_clear_error (&error);
    }

    g_mutex_lock (&job->mutex);
    job->running--;
    job->first_run = FALSE;
    g_mutex_unlock (&job->mutex);
    g_free (filename);
}


static void
dec_exec_thread (gpointer data, gpointer user_data)
{
    gchar *filename = data;
    CryptoJobData *job = user_data;

    g_mutex_lock (&job->mutex);
    job->running++;
    g_mutex_unlock (&job->mutex);
    g_free (filename);

    g_autofree gchar *output = g_str_has_suffix (filename, ".enc") ?
        g_strndup (filename, strlen (filename) - 4) :
        g_strconcat (filename, ".decrypted", NULL);
    GError *error = NULL;
    gboolean ok = gtkcrypto_decrypt_file (
        filename, output, (const guint8 *)job->pwd, strlen (job->pwd),
        job->overwrite, NULL, &error);
    if (!ok) {
        g_mutex_lock (&job->mutex);
        job->failed++;
        g_mutex_unlock (&job->mutex);
        g_clear_error (&error);
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
    g_object_unref (d->spinner);
    g_object_unref (d->overlay);
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
            d->spinner = g_object_ref (job->page->enc_spinner);
            d->overlay = g_object_ref (job->page->enc_toast_overlay);
            gtk_widget_set_sensitive (job->page->encrypt_btn, TRUE);
        } else {
            d->spinner = g_object_ref (job->page->dec_spinner);
            d->overlay = g_object_ref (job->page->dec_toast_overlay);
            gtk_widget_set_sensitive (job->page->decrypt_btn, TRUE);
        }
        g_idle_add (job_done_idle, d);

        gcry_free (job->pwd);
        g_mutex_clear (&job->mutex);
        g_object_unref (job->page);
        g_free (job);
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}


/* ---- File chooser ---- */

static void
set_enc_files (GtkcryptoFileCryptoPage *self, GSList *paths /* takes ownership */)
{
    g_slist_free_full (self->enc_files_list, g_free);
    self->enc_files_list = paths;
    guint n = g_slist_length (paths);
    g_autofree gchar *label = g_strdup_printf ("%u file(s) selected", n);
    gtk_label_set_text (self->enc_file_label, label);
}

static void
set_dec_files (GtkcryptoFileCryptoPage *self, GSList *paths /* takes ownership */)
{
    g_slist_free_full (self->dec_files_list, g_free);
    self->dec_files_list = paths;
    guint n = g_slist_length (paths);
    g_autofree gchar *label = g_strdup_printf ("%u file(s) selected", n);
    gtk_label_set_text (self->dec_file_label, label);
}

static GSList *
paths_from_list_model (GListModel *files)
{
    GSList *paths = NULL;
    guint n = g_list_model_get_n_items (files);
    for (guint i = 0; i < n; i++) {
        g_autoptr(GFile) f = g_list_model_get_item (files, i);
        paths = g_slist_prepend (paths, g_file_get_path (f));
    }
    return g_slist_reverse (paths);
}

static GSList *
paths_from_file_list (GdkFileList *file_list)
{
    GSList *paths = NULL;
    for (GSList *l = gdk_file_list_get_files (file_list); l; l = l->next) {
        paths = g_slist_prepend (paths, g_file_get_path (G_FILE (l->data)));
    }
    return g_slist_reverse (paths);
}

static void
enc_files_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoFileCryptoPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GListModel) files = gtk_file_dialog_open_multiple_finish (dialog, result, NULL);
    if (files == NULL) return;
    set_enc_files (self, paths_from_list_model (files));
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
    set_dec_files (self, paths_from_list_model (files));
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


/* ---- Drag and drop ---- */

static GdkDragAction
file_drop_enter_cb (GtkDropTarget *target, double x, double y, gpointer user_data)
{
    (void)target; (void)x; (void)y;
    gtk_widget_add_css_class (GTK_WIDGET (user_data), "drop-target-active");
    return GDK_ACTION_COPY;
}

static void
file_drop_leave_cb (GtkDropTarget *target, gpointer user_data)
{
    (void)target;
    gtk_widget_remove_css_class (GTK_WIDGET (user_data), "drop-target-active");
}

static gboolean
enc_files_drop_cb (GtkDropTarget *target, const GValue *value, double x, double y, gpointer user_data)
{
    (void)target; (void)x; (void)y;
    if (!G_VALUE_HOLDS (value, GDK_TYPE_FILE_LIST)) return FALSE;
    GdkFileList *fl = g_value_get_boxed (value);
    if (fl == NULL) return FALSE;
    set_enc_files (user_data, paths_from_file_list (fl));
    return TRUE;
}

static gboolean
dec_files_drop_cb (GtkDropTarget *target, const GValue *value, double x, double y, gpointer user_data)
{
    (void)target; (void)x; (void)y;
    if (!G_VALUE_HOLDS (value, GDK_TYPE_FILE_LIST)) return FALSE;
    GdkFileList *fl = g_value_get_boxed (value);
    if (fl == NULL) return FALSE;
    set_dec_files (user_data, paths_from_file_list (fl));
    return TRUE;
}

static void
attach_files_drop (GtkWidget *target_widget, GCallback drop_cb, gpointer user_data)
{
    GtkDropTarget *target = gtk_drop_target_new (GDK_TYPE_FILE_LIST, GDK_ACTION_COPY);
    g_signal_connect (target, "drop", drop_cb, user_data);
    g_signal_connect (target, "enter", G_CALLBACK (file_drop_enter_cb), target_widget);
    g_signal_connect (target, "leave", G_CALLBACK (file_drop_leave_cb), target_widget);
    gtk_widget_add_controller (target_widget, GTK_EVENT_CONTROLLER (target));
}


/* ---- Encrypt/Decrypt actions ---- */

static void
show_toast (AdwToastOverlay *overlay, const gchar *msg)
{
    adw_toast_overlay_add_toast (overlay, adw_toast_new (msg));
}


static void
start_encrypt_job (GtkcryptoFileCryptoPage *self, gboolean overwrite)
{
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

    CryptoJobData *job = g_new0 (CryptoJobData, 1);
    job->page = g_object_ref (self);
    gsize pwd_len = strlen (pwd) + 1;
    job->pwd = gcry_malloc_secure (pwd_len);
    memcpy (job->pwd, pwd, pwd_len);
    gtk_editable_set_text (GTK_EDITABLE (self->enc_pwd_row), "");
    gtk_editable_set_text (GTK_EDITABLE (self->enc_pwd_confirm_row), "");
    job->total = g_slist_length (self->enc_files_list);
    job->first_run = TRUE;
    job->is_encrypt = TRUE;
    job->overwrite = overwrite;
    g_mutex_init (&job->mutex);

    gtk_widget_set_sensitive (self->encrypt_btn, FALSE);
    gtk_spinner_start (self->enc_spinner);

    GError *pool_error = NULL;
    job->pool = g_thread_pool_new (enc_exec_thread, job,
                                    (gint)MIN (4, g_get_num_processors ()),
                                    TRUE, &pool_error);
    if (job->pool == NULL) {
        show_toast (self->enc_toast_overlay, pool_error->message);
        g_clear_error (&pool_error);
        gtk_widget_set_sensitive (self->encrypt_btn, TRUE);
        gtk_spinner_stop (self->enc_spinner);
        gcry_free (job->pwd);
        g_mutex_clear (&job->mutex);
        g_object_unref (job->page);
        g_free (job);
        return;
    }
    for (GSList *l = self->enc_files_list; l; l = l->next) {
        g_thread_pool_push (job->pool, g_strdup (l->data), NULL);
    }

    job->source_id = g_timeout_add (500, check_job_done, job);
}

typedef struct {
    GtkcryptoFileCryptoPage *page;
    gboolean encrypt;
} OverwritePromptData;

static void
overwrite_prompt_done (GObject *source, GAsyncResult *result,
                       gpointer user_data)
{
    OverwritePromptData *data = user_data;
    const gchar *response = adw_alert_dialog_choose_finish (
        ADW_ALERT_DIALOG (source), result);
    if (g_strcmp0 (response, "replace") == 0) {
        if (data->encrypt) {
            start_encrypt_job (data->page, TRUE);
        } else {
            start_decrypt_job (data->page, TRUE);
        }
    }
    g_object_unref (data->page);
    g_free (data);
}

static void
prompt_overwrite (GtkcryptoFileCryptoPage *self, gboolean encrypt)
{
    AdwAlertDialog *dialog = ADW_ALERT_DIALOG (adw_alert_dialog_new (
        "Replace existing files?",
        "One or more destination files already exist. Replacement occurs "
        "atomically only after the operation succeeds."));
    adw_alert_dialog_add_response (dialog, "cancel", "Cancel");
    adw_alert_dialog_add_response (dialog, "replace", "Replace");
    adw_alert_dialog_set_default_response (dialog, "cancel");
    adw_alert_dialog_set_close_response (dialog, "cancel");
    adw_alert_dialog_set_response_appearance (
        dialog, "replace", ADW_RESPONSE_DESTRUCTIVE);
    OverwritePromptData *data = g_new0 (OverwritePromptData, 1);
    data->page = g_object_ref (self);
    data->encrypt = encrypt;
    adw_alert_dialog_choose (dialog, GTK_WIDGET (self), NULL,
                             overwrite_prompt_done, data);
}

static gboolean
encryption_destination_exists (GtkcryptoFileCryptoPage *self)
{
    for (GSList *l = self->enc_files_list; l; l = l->next) {
        g_autofree gchar *output = g_strconcat (l->data, ".enc", NULL);
        if (g_file_test (output, G_FILE_TEST_EXISTS)) {
            return TRUE;
        }
    }
    return FALSE;
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
    if (encryption_destination_exists (self)) {
        prompt_overwrite (self, TRUE);
        return;
    }
    start_encrypt_job (self, FALSE);
}


static void
start_decrypt_job (GtkcryptoFileCryptoPage *self, gboolean overwrite)
{
    const gchar *pwd = gtk_editable_get_text (GTK_EDITABLE (self->dec_pwd_row));
    if (g_utf8_strlen (pwd, -1) < 8) {
        show_toast (self->dec_toast_overlay, "Password must be at least 8 characters");
        return;
    }

    CryptoJobData *job = g_new0 (CryptoJobData, 1);
    job->page = g_object_ref (self);
    gsize pwd_len = strlen (pwd) + 1;
    job->pwd = gcry_malloc_secure (pwd_len);
    memcpy (job->pwd, pwd, pwd_len);
    gtk_editable_set_text (GTK_EDITABLE (self->dec_pwd_row), "");
    job->total = g_slist_length (self->dec_files_list);
    job->first_run = TRUE;
    job->is_encrypt = FALSE;
    job->delete_file = gtk_switch_get_active (self->delete_switch);
    job->overwrite = overwrite;
    g_mutex_init (&job->mutex);

    gtk_widget_set_sensitive (self->decrypt_btn, FALSE);
    gtk_spinner_start (self->dec_spinner);

    GError *pool_error = NULL;
    job->pool = g_thread_pool_new (dec_exec_thread, job,
                                    (gint)MIN (4, g_get_num_processors ()),
                                    TRUE, &pool_error);
    if (job->pool == NULL) {
        show_toast (self->dec_toast_overlay, pool_error->message);
        g_clear_error (&pool_error);
        gtk_widget_set_sensitive (self->decrypt_btn, TRUE);
        gtk_spinner_stop (self->dec_spinner);
        gcry_free (job->pwd);
        g_mutex_clear (&job->mutex);
        g_object_unref (job->page);
        g_free (job);
        return;
    }
    for (GSList *l = self->dec_files_list; l; l = l->next) {
        g_thread_pool_push (job->pool, g_strdup (l->data), NULL);
    }

    job->source_id = g_timeout_add (500, check_job_done, job);
}

static gboolean
decryption_destination_exists (GtkcryptoFileCryptoPage *self)
{
    for (GSList *l = self->dec_files_list; l; l = l->next) {
        const gchar *input = l->data;
        g_autofree gchar *output = g_str_has_suffix (input, ".enc") ?
            g_strndup (input, strlen (input) - 4) :
            g_strconcat (input, ".decrypted", NULL);
        if (g_file_test (output, G_FILE_TEST_EXISTS)) {
            return TRUE;
        }
    }
    return FALSE;
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
    if (decryption_destination_exists (self)) {
        prompt_overwrite (self, FALSE);
        return;
    }
    start_decrypt_job (self, FALSE);
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
    attach_files_drop (file_row, G_CALLBACK (enc_files_drop_cb), self);

    /* Cipher and mode */
    GtkWidget *crypto_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (crypto_group), "Encryption Settings");

    GtkWidget *cipher_row = adw_action_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (cipher_row),
                                   "AES-256-GCM");
    adw_action_row_set_subtitle (ADW_ACTION_ROW (cipher_row),
                                 "Authenticated encryption");
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (crypto_group),
                               cipher_row);

    GtkWidget *kdf_row = adw_action_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (kdf_row),
                                   "Argon2id");
    adw_action_row_set_subtitle (ADW_ACTION_ROW (kdf_row),
                                 "Memory-hard password derivation");
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (crypto_group),
                               kdf_row);

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
    self->encrypt_btn = gtk_button_new ();
    GtkWidget *enc_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append (GTK_BOX (enc_box), gtk_image_new_from_icon_name ("channel-secure-symbolic"));
    gtk_box_append (GTK_BOX (enc_box), gtk_label_new ("Encrypt"));
    gtk_button_set_child (GTK_BUTTON (self->encrypt_btn), enc_box);
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
    attach_files_drop (file_row, G_CALLBACK (dec_files_drop_cb), self);

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
    self->decrypt_btn = gtk_button_new ();
    GtkWidget *dec_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append (GTK_BOX (dec_box), gtk_image_new_from_icon_name ("channel-insecure-symbolic"));
    gtk_box_append (GTK_BOX (dec_box), gtk_label_new ("Decrypt"));
    gtk_button_set_child (GTK_BUTTON (self->decrypt_btn), dec_box);
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
    AdwViewStackPage *enc_vs_page = adw_view_stack_add_titled (self->view_stack, enc_page, "encrypt", "Encrypt");
    adw_view_stack_page_set_icon_name (enc_vs_page, "channel-secure-symbolic");

    GtkWidget *dec_page = build_decrypt_page (self);
    AdwViewStackPage *dec_vs_page = adw_view_stack_add_titled (self->view_stack, dec_page, "decrypt", "Decrypt");
    adw_view_stack_page_set_icon_name (dec_vs_page, "channel-insecure-symbolic");

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
