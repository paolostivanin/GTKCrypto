#include <errno.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/stat.h>
#include "file-crypto-page.h"
#include "../encrypt-files-cb.h"
#include "../decrypt-files-cb.h"
#include "../crypt-common.h"
#include "../password-utils.h"

#define MIN_ENCRYPT_PWD_LEN  8
#define GENERATED_PWD_LEN    20
#define MAX_ERROR_LINES      10

/* One of the two sub-pages (Encrypt / Decrypt). They share all logic and only
 * differ in a few widgets, so everything below works on a Panel. */
typedef struct {
    GtkcryptoFileCryptoPage *page;
    gboolean                 is_encrypt;

    GSList          *files;            /* gchar *path, owned */
    gchar           *output_dir;       /* NULL = next to the input file */

    GtkWidget       *inputs_box;       /* insensitive while a job runs */
    GtkWidget       *files_group;
    GtkListBox      *file_list;
    GtkWidget       *clear_btn;
    AdwActionRow    *output_row;
    GtkWidget       *output_reset_btn;
    AdwPasswordEntryRow *pwd_row;
    AdwPasswordEntryRow *confirm_row;  /* encrypt only */
    GtkLevelBar     *strength_bar;     /* encrypt only */
    GtkLabel        *strength_label;   /* encrypt only */
    GtkSwitch       *delete_switch;
    GtkWidget       *action_btn;
    GtkWidget       *cancel_btn;
    GtkProgressBar  *progress;
    AdwToastOverlay *overlay;
    GCancellable    *cancellable;      /* of the running job, if any */
} Panel;

struct _GtkcryptoFileCryptoPage {
    GtkBox parent_instance;

    AdwViewStack *view_stack;
    Panel         enc;
    Panel         dec;

    gint          busy_workers;   /* atomic: tasks still inside the core */
};

G_DEFINE_TYPE (GtkcryptoFileCryptoPage, gtkcrypto_file_crypto_page, GTK_TYPE_BOX)

typedef struct {
    Panel                   *panel;
    GtkcryptoFileCryptoPage *page;
    GMutex                   mutex;
    guint                    done;
    guint                    failed;
    guint                    total;
    guint64                  bytes_done;
    guint64                  bytes_total;
    gchar                   *pwd;
    GThreadPool             *pool;
    gboolean                 is_encrypt;
    gboolean                 delete_source;
    gboolean                 overwrite;
    gchar                   *output_dir;
    GCancellable            *cancellable;
    GPtrArray               *errors;    /* "name: message" per problem */
} CryptoJobData;

static void start_job (Panel *p, gboolean overwrite);


/* ---- Helpers ---- */

static void
set_a11y (GtkWidget *widget, const gchar *label)
{
    gtk_widget_set_tooltip_text (widget, label);
    gtk_accessible_update_property (GTK_ACCESSIBLE (widget),
                                    GTK_ACCESSIBLE_PROPERTY_LABEL, label, -1);
}

static void
show_toast (Panel *p, const gchar *msg)
{
    adw_toast_overlay_add_toast (p->overlay, adw_toast_new (msg));
}

static GtkWindow *
panel_window (Panel *p)
{
    GtkRoot *root = gtk_widget_get_root (GTK_WIDGET (p->page));
    return GTK_IS_WINDOW (root) ? GTK_WINDOW (root) : NULL;
}

static gchar *
build_output_path (const gchar *input, gboolean is_encrypt,
                   const gchar *output_dir)
{
    g_autofree gchar *base = g_path_get_basename (input);
    g_autofree gchar *name = NULL;
    if (is_encrypt) {
        name = g_strconcat (base, ".enc", NULL);
    } else if (g_str_has_suffix (base, ".enc") && strlen (base) > 4) {
        name = g_strndup (base, strlen (base) - 4);
    } else {
        name = g_strconcat (base, ".decrypted", NULL);
    }
    if (output_dir != NULL) {
        return g_build_filename (output_dir, name, NULL);
    }
    g_autofree gchar *dir = g_path_get_dirname (input);
    return g_build_filename (dir, name, NULL);
}

static guint64
file_size_of (const gchar *path)
{
    GStatBuf st;
    if (g_stat (path, &st) != 0 || st.st_size < 0) {
        return 0;
    }
    return (guint64)st.st_size;
}


/* ---- Worker threads ---- */

typedef struct {
    CryptoJobData *job;
    guint64        reported;
} FileProgress;

static void
job_add_bytes (CryptoJobData *job, guint64 delta)
{
    g_mutex_lock (&job->mutex);
    job->bytes_done += delta;
    g_mutex_unlock (&job->mutex);
}

static void
file_progress_cb (guint64 done, guint64 total, gpointer user_data)
{
    (void)total;
    FileProgress *fp = user_data;
    if (done > fp->reported) {
        job_add_bytes (fp->job, done - fp->reported);
        fp->reported = done;
    }
}

static void
job_record_failure (CryptoJobData *job, const gchar *filename,
                    const GError *error)
{
    g_autofree gchar *base = g_path_get_basename (filename);

    g_mutex_lock (&job->mutex);
    job->failed++;
    if (error == NULL ||
        !g_error_matches (error, GTKCRYPTO_ERROR,
                          GTKCRYPTO_ERROR_CANCELLED)) {
        g_ptr_array_add (job->errors,
                         g_strdup_printf ("%s: %s", base,
                                          error ? error->message
                                                : _("Unknown error")));
    }
    g_mutex_unlock (&job->mutex);
}

static void
job_exec_thread (gpointer data, gpointer user_data)
{
    gchar *filename = data;
    CryptoJobData *job = user_data;

    g_autofree gchar *output = build_output_path (filename, job->is_encrypt,
                                                  job->output_dir);
    guint64 size = file_size_of (filename);
    FileProgress fp = { job, 0 };
    g_autoptr(GError) error = NULL;

    gtkcrypto_set_progress (file_progress_cb, &fp);
    gboolean ok = gtkcrypto_check_cancelled (job->cancellable, &error);
    if (ok) {
        ok = job->is_encrypt ?
            gtkcrypto_encrypt_file (filename, output,
                                    (const guint8 *)job->pwd, strlen (job->pwd),
                                    job->overwrite, job->cancellable, &error) :
            gtkcrypto_decrypt_file (filename, output,
                                    (const guint8 *)job->pwd, strlen (job->pwd),
                                    job->overwrite, job->cancellable, &error);
    }
    gtkcrypto_set_progress (NULL, NULL);

    /* Account for whatever the progress callback did not report (legacy
     * formats, header/tag overhead) so the bar never stalls. */
    if (size > fp.reported) {
        job_add_bytes (job, size - fp.reported);
    }

    if (!ok) {
        job_record_failure (job, filename, error);
    } else if (job->delete_source && g_unlink (filename) != 0) {
        g_autofree gchar *base = g_path_get_basename (filename);
        g_mutex_lock (&job->mutex);
        g_ptr_array_add (job->errors,
                         g_strdup_printf (_("%s: processed, but the original "
                                            "file could not be deleted: %s"),
                                          base, g_strerror (errno)));
        g_mutex_unlock (&job->mutex);
    }

    g_atomic_int_dec_and_test (&job->page->busy_workers);
    g_mutex_lock (&job->mutex);
    job->done++;
    g_mutex_unlock (&job->mutex);
    g_free (filename);
}


/* ---- Job completion (main thread, polled) ---- */

static void
show_error_details (CryptoJobData *job)
{
    GString *body = g_string_new (NULL);
    for (guint i = 0; i < job->errors->len && i < MAX_ERROR_LINES; i++) {
        g_string_append_printf (body, "%s%s", i ? "\n" : "",
                                (const gchar *)g_ptr_array_index (job->errors, i));
    }
    if (job->errors->len > MAX_ERROR_LINES) {
        g_string_append_printf (body, _("\n… and %u more"),
                                job->errors->len - MAX_ERROR_LINES);
    }

    AdwAlertDialog *dialog = ADW_ALERT_DIALOG (adw_alert_dialog_new (
        job->is_encrypt ? _("Some files could not be encrypted")
                        : _("Some files could not be decrypted"),
        body->str));
    adw_alert_dialog_add_response (dialog, "close", _("Close"));
    adw_alert_dialog_set_default_response (dialog, "close");
    adw_alert_dialog_set_close_response (dialog, "close");
    adw_dialog_present (ADW_DIALOG (dialog), GTK_WIDGET (job->page));
    g_string_free (body, TRUE);
}

static gchar *
job_summary (CryptoJobData *job, gboolean cancelled)
{
    guint ok = job->total - job->failed;
    if (job->is_encrypt) {
        if (cancelled) {
            return g_strdup_printf (ngettext ("Cancelled: %u of %u file encrypted",
                                              "Cancelled: %u of %u files encrypted",
                                              job->total), ok, job->total);
        }
        return g_strdup_printf (ngettext ("%u of %u file encrypted",
                                          "%u of %u files encrypted",
                                          job->total), ok, job->total);
    }
    if (cancelled) {
        return g_strdup_printf (ngettext ("Cancelled: %u of %u file decrypted",
                                          "Cancelled: %u of %u files decrypted",
                                          job->total), ok, job->total);
    }
    return g_strdup_printf (ngettext ("%u of %u file decrypted",
                                      "%u of %u files decrypted",
                                      job->total), ok, job->total);
}

static void
panel_update_progress (Panel *p, CryptoJobData *job)
{
    g_mutex_lock (&job->mutex);
    guint64 bytes_done = job->bytes_done;
    guint files_done = job->done;
    g_mutex_unlock (&job->mutex);

    gdouble fraction = job->bytes_total > 0 ?
        (gdouble)MIN (bytes_done, job->bytes_total) / (gdouble)job->bytes_total :
        (gdouble)files_done / (gdouble)MAX (job->total, 1);
    gtk_progress_bar_set_fraction (p->progress, fraction);

    g_autofree gchar *text = g_strdup_printf (
        ngettext ("%u / %u file · %d%%", "%u / %u files · %d%%", job->total),
        files_done, job->total, (gint)(fraction * 100.0));
    gtk_progress_bar_set_text (p->progress, text);
}

static gboolean
check_job_done (gpointer user_data)
{
    CryptoJobData *job = user_data;
    Panel *p = job->panel;

    g_mutex_lock (&job->mutex);
    gboolean finished = job->done >= job->total;
    g_mutex_unlock (&job->mutex);

    if (!finished) {
        panel_update_progress (p, job);
        return G_SOURCE_CONTINUE;
    }

    g_thread_pool_free (job->pool, FALSE, TRUE);

    gboolean cancelled = g_cancellable_is_cancelled (job->cancellable);
    g_autofree gchar *summary = job_summary (job, cancelled);
    show_toast (p, summary);

    gtk_widget_set_visible (GTK_WIDGET (p->progress), FALSE);
    gtk_widget_set_visible (p->cancel_btn, FALSE);
    gtk_widget_set_sensitive (p->action_btn, TRUE);
    gtk_widget_set_sensitive (p->inputs_box, TRUE);
    g_clear_object (&p->cancellable);

    /* Keep the password after a failure so a typo does not mean retyping
     * everything; wipe it once everything went through. */
    if (job->failed == 0 && !cancelled) {
        gtk_editable_set_text (GTK_EDITABLE (p->pwd_row), "");
        if (p->confirm_row != NULL) {
            gtk_editable_set_text (GTK_EDITABLE (p->confirm_row), "");
        }
    }

    if (job->errors->len > 0) {
        show_error_details (job);
    }

    gcry_free (job->pwd);
    g_free (job->output_dir);
    g_ptr_array_free (job->errors, TRUE);
    g_object_unref (job->cancellable);
    g_mutex_clear (&job->mutex);
    g_object_unref (job->page);
    g_free (job);
    return G_SOURCE_REMOVE;
}


/* ---- File list ---- */

static void remove_file_clicked_cb (GtkButton *btn, gpointer user_data);

static void
panel_rebuild_rows (Panel *p)
{
    gtk_list_box_remove_all (p->file_list);

    guint n = g_slist_length (p->files);
    if (n == 0) {
        GtkWidget *row = adw_action_row_new ();
        adw_preferences_row_set_use_markup (ADW_PREFERENCES_ROW (row), FALSE);
        adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row),
                                       _("No files selected"));
        adw_action_row_set_subtitle (ADW_ACTION_ROW (row),
                                     _("Drop files here or use “Add files”"));
        gtk_widget_add_css_class (row, "dim-label");
        gtk_list_box_append (p->file_list, row);
    }

    guint index = 0;
    for (GSList *l = p->files; l; l = l->next, index++) {
        g_autofree gchar *base = g_path_get_basename (l->data);
        g_autofree gchar *dir = g_path_get_dirname (l->data);

        GtkWidget *row = adw_action_row_new ();
        adw_preferences_row_set_use_markup (ADW_PREFERENCES_ROW (row), FALSE);
        adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row), base);
        adw_action_row_set_subtitle (ADW_ACTION_ROW (row), dir);
        adw_action_row_set_subtitle_lines (ADW_ACTION_ROW (row), 1);

        GtkWidget *rm = gtk_button_new_from_icon_name ("list-remove-symbolic");
        gtk_widget_set_valign (rm, GTK_ALIGN_CENTER);
        gtk_widget_add_css_class (rm, "flat");
        g_autofree gchar *label = g_strdup_printf (_("Remove %s from the list"),
                                                   base);
        set_a11y (rm, label);
        g_object_set_data (G_OBJECT (rm), "index", GUINT_TO_POINTER (index));
        g_signal_connect (rm, "clicked", G_CALLBACK (remove_file_clicked_cb), p);
        adw_action_row_add_suffix (ADW_ACTION_ROW (row), rm);
        gtk_list_box_append (p->file_list, row);
    }

    g_autofree gchar *desc = n == 0 ? g_strdup ("") :
        g_strdup_printf (ngettext ("%u file selected", "%u files selected", n), n);
    adw_preferences_group_set_description (ADW_PREFERENCES_GROUP (p->files_group),
                                           desc);
    gtk_widget_set_sensitive (p->clear_btn, n > 0);
}

static void
remove_file_clicked_cb (GtkButton *btn, gpointer user_data)
{
    Panel *p = user_data;
    gpointer data = g_object_get_data (G_OBJECT (btn), "index");
    guint index = GPOINTER_TO_UINT (data);
    GSList *link = g_slist_nth (p->files, index);
    if (link != NULL) {
        g_free (link->data);
        p->files = g_slist_delete_link (p->files, link);
    }
    panel_rebuild_rows (p);
}

static void
clear_files_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    Panel *p = user_data;
    g_slist_free_full (p->files, g_free);
    p->files = NULL;
    panel_rebuild_rows (p);
}

/* Appends PATHS (takes ownership of the list and strings) to the panel,
 * skipping duplicates and directories. */
static void
panel_add_paths (Panel *p, GSList *paths)
{
    guint dirs = 0, dups = 0;
    for (GSList *l = paths; l; l = l->next) {
        gchar *path = l->data;
        if (g_file_test (path, G_FILE_TEST_IS_DIR)) {
            dirs++;
            g_free (path);
        } else if (g_slist_find_custom (p->files, path, (GCompareFunc)g_strcmp0)) {
            dups++;
            g_free (path);
        } else {
            p->files = g_slist_append (p->files, path);
        }
    }
    g_slist_free (paths);
    panel_rebuild_rows (p);

    if (dirs > 0) {
        g_autofree gchar *msg = g_strdup_printf (
            ngettext ("Skipped %u folder: only files can be processed",
                      "Skipped %u folders: only files can be processed", dirs),
            dirs);
        show_toast (p, msg);
    } else if (dups > 0) {
        g_autofree gchar *msg = g_strdup_printf (
            ngettext ("%u file was already in the list",
                      "%u files were already in the list", dups), dups);
        show_toast (p, msg);
    }
}

static GSList *
paths_from_list_model (GListModel *files)
{
    GSList *paths = NULL;
    guint n = g_list_model_get_n_items (files);
    for (guint i = 0; i < n; i++) {
        g_autoptr(GFile) f = g_list_model_get_item (files, i);
        gchar *path = g_file_get_path (f);
        if (path != NULL) {
            paths = g_slist_prepend (paths, path);
        }
    }
    return g_slist_reverse (paths);
}

static GSList *
paths_from_file_list (GdkFileList *file_list)
{
    GSList *paths = NULL;
    for (GSList *l = gdk_file_list_get_files (file_list); l; l = l->next) {
        gchar *path = g_file_get_path (G_FILE (l->data));
        if (path != NULL) {
            paths = g_slist_prepend (paths, path);
        }
    }
    return g_slist_reverse (paths);
}

static void
files_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    Panel *p = user_data;
    g_autoptr(GListModel) files = gtk_file_dialog_open_multiple_finish (
        GTK_FILE_DIALOG (source), result, NULL);
    if (files == NULL) return;
    panel_add_paths (p, paths_from_list_model (files));
}

static void
add_files_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    Panel *p = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, p->is_encrypt ?
                               _("Choose file(s) to encrypt") :
                               _("Choose file(s) to decrypt"));
    gtk_file_dialog_open_multiple (dialog, panel_window (p), NULL,
                                   files_chosen_cb, p);
    g_object_unref (dialog);
}


/* ---- Output folder ---- */

static void
panel_update_output_row (Panel *p)
{
    adw_action_row_set_subtitle (p->output_row, p->output_dir != NULL ?
                                 p->output_dir : _("Next to the original file"));
    gtk_widget_set_sensitive (p->output_reset_btn, p->output_dir != NULL);
}

static void
folder_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    Panel *p = user_data;
    g_autoptr(GFile) folder = gtk_file_dialog_select_folder_finish (
        GTK_FILE_DIALOG (source), result, NULL);
    if (folder == NULL) return;
    gchar *path = g_file_get_path (folder);
    if (path == NULL) {
        show_toast (p, _("Please choose a local folder"));
        return;
    }
    g_free (p->output_dir);
    p->output_dir = path;
    panel_update_output_row (p);
}

static void
choose_output_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    Panel *p = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, _("Choose output folder"));
    gtk_file_dialog_select_folder (dialog, panel_window (p), NULL,
                                   folder_chosen_cb, p);
    g_object_unref (dialog);
}

static void
reset_output_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    Panel *p = user_data;
    g_clear_pointer (&p->output_dir, g_free);
    panel_update_output_row (p);
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
files_drop_cb (GtkDropTarget *target, const GValue *value, double x, double y,
               gpointer user_data)
{
    (void)target; (void)x; (void)y;
    Panel *p = user_data;
    gtk_widget_remove_css_class (p->files_group, "drop-target-active");
    if (!G_VALUE_HOLDS (value, GDK_TYPE_FILE_LIST)) return FALSE;
    GdkFileList *fl = g_value_get_boxed (value);
    if (fl == NULL) return FALSE;
    panel_add_paths (p, paths_from_file_list (fl));
    return TRUE;
}

static void
attach_files_drop (Panel *p)
{
    GtkDropTarget *target = gtk_drop_target_new (GDK_TYPE_FILE_LIST, GDK_ACTION_COPY);
    g_signal_connect (target, "drop", G_CALLBACK (files_drop_cb), p);
    g_signal_connect (target, "enter", G_CALLBACK (file_drop_enter_cb), p->files_group);
    g_signal_connect (target, "leave", G_CALLBACK (file_drop_leave_cb), p->files_group);
    gtk_widget_add_controller (p->files_group, GTK_EVENT_CONTROLLER (target));
}


/* ---- Overwrite prompt ---- */

static void
overwrite_prompt_done (GObject *source, GAsyncResult *result,
                       gpointer user_data)
{
    Panel *p = user_data;
    const gchar *response = adw_alert_dialog_choose_finish (
        ADW_ALERT_DIALOG (source), result);
    if (g_strcmp0 (response, "replace") == 0) {
        start_job (p, TRUE);
    }
}

static void
prompt_overwrite (Panel *p)
{
    AdwAlertDialog *dialog = ADW_ALERT_DIALOG (adw_alert_dialog_new (
        _("Replace existing files?"),
        _("One or more destination files already exist. Replacement occurs "
          "atomically only after the operation succeeds.")));
    adw_alert_dialog_add_response (dialog, "cancel", _("Cancel"));
    adw_alert_dialog_add_response (dialog, "replace", _("Replace"));
    adw_alert_dialog_set_default_response (dialog, "cancel");
    adw_alert_dialog_set_close_response (dialog, "cancel");
    adw_alert_dialog_set_response_appearance (
        dialog, "replace", ADW_RESPONSE_DESTRUCTIVE);
    adw_alert_dialog_choose (dialog, GTK_WIDGET (p->page), NULL,
                             overwrite_prompt_done, p);
}

/* TRUE if two inputs would write to the same destination. */
static gboolean
panel_outputs_collide (Panel *p)
{
    g_autoptr(GHashTable) seen = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                        g_free, NULL);
    for (GSList *l = p->files; l; l = l->next) {
        gchar *output = build_output_path (l->data, p->is_encrypt, p->output_dir);
        if (!g_hash_table_add (seen, output)) {
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean
panel_destination_exists (Panel *p)
{
    for (GSList *l = p->files; l; l = l->next) {
        g_autofree gchar *output = build_output_path (l->data, p->is_encrypt,
                                                      p->output_dir);
        if (g_file_test (output, G_FILE_TEST_EXISTS)) {
            return TRUE;
        }
    }
    return FALSE;
}

static void
action_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    Panel *p = user_data;
    if (p->files == NULL) {
        show_toast (p, _("No files selected"));
        return;
    }
    if (panel_outputs_collide (p)) {
        show_toast (p, _("Several files would produce the same output name; "
                         "choose a different output folder or remove duplicates"));
        return;
    }
    if (panel_destination_exists (p)) {
        prompt_overwrite (p);
        return;
    }
    start_job (p, FALSE);
}


/* ---- Starting a job ---- */

static void
start_job (Panel *p, gboolean overwrite)
{
    GtkcryptoFileCryptoPage *self = p->page;
    const gchar *pwd = gtk_editable_get_text (GTK_EDITABLE (p->pwd_row));

    if (p->is_encrypt) {
        const gchar *confirm = gtk_editable_get_text (GTK_EDITABLE (p->confirm_row));
        if (g_utf8_strlen (pwd, -1) < MIN_ENCRYPT_PWD_LEN) {
            show_toast (p, _("Password must be at least 8 characters"));
            return;
        }
        if (g_strcmp0 (pwd, confirm) != 0) {
            show_toast (p, _("Passwords do not match"));
            return;
        }
    } else if (*pwd == '\0') {
        /* Older files may use short passwords, so only require something. */
        show_toast (p, _("Enter the password"));
        return;
    }

    CryptoJobData *job = g_new0 (CryptoJobData, 1);
    gsize pwd_len = strlen (pwd) + 1;
    job->pwd = gcry_malloc_secure (pwd_len);
    if (job->pwd == NULL) {
        show_toast (p, _("Unable to allocate secure memory for the password"));
        g_free (job);
        return;
    }
    memcpy (job->pwd, pwd, pwd_len);

    job->panel = p;
    job->page = g_object_ref (self);
    job->is_encrypt = p->is_encrypt;
    job->delete_source = gtk_switch_get_active (p->delete_switch);
    job->overwrite = overwrite;
    job->output_dir = g_strdup (p->output_dir);
    job->total = g_slist_length (p->files);
    for (GSList *l = p->files; l; l = l->next) {
        job->bytes_total += file_size_of (l->data);
    }
    g_mutex_init (&job->mutex);
    job->errors = g_ptr_array_new_with_free_func (g_free);
    job->cancellable = g_cancellable_new ();
    g_set_object (&p->cancellable, job->cancellable);
    g_atomic_int_add (&self->busy_workers, (gint)job->total);

    GError *pool_error = NULL;
    job->pool = g_thread_pool_new (job_exec_thread, job,
                                   (gint)MIN (4, g_get_num_processors ()),
                                   TRUE, &pool_error);
    if (job->pool == NULL) {
        show_toast (p, pool_error->message);
        g_clear_error (&pool_error);
        g_atomic_int_add (&self->busy_workers, -(gint)job->total);
        g_clear_object (&p->cancellable);
        gcry_free (job->pwd);
        g_free (job->output_dir);
        g_ptr_array_free (job->errors, TRUE);
        g_object_unref (job->cancellable);
        g_mutex_clear (&job->mutex);
        g_object_unref (job->page);
        g_free (job);
        return;
    }

    gtk_widget_set_sensitive (p->action_btn, FALSE);
    gtk_widget_set_sensitive (p->inputs_box, FALSE);
    gtk_widget_set_visible (p->cancel_btn, TRUE);
    gtk_progress_bar_set_fraction (p->progress, 0.0);
    panel_update_progress (p, job);
    gtk_widget_set_visible (GTK_WIDGET (p->progress), TRUE);

    for (GSList *l = p->files; l; l = l->next) {
        g_thread_pool_push (job->pool, g_strdup (l->data), NULL);
    }
    g_timeout_add (200, check_job_done, job);
}


/* ---- Cancel / shutdown ---- */

static void
cancel_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    Panel *p = user_data;
    if (p->cancellable != NULL) {
        g_cancellable_cancel (p->cancellable);
    }
}

/* Cancel running jobs and wait (briefly) for workers to leave the core, so
 * temporary output files are removed before the application exits. */
void
gtkcrypto_file_crypto_page_shutdown (GtkcryptoFileCryptoPage *self)
{
    if (self->enc.cancellable != NULL) g_cancellable_cancel (self->enc.cancellable);
    if (self->dec.cancellable != NULL) g_cancellable_cancel (self->dec.cancellable);
    for (gint i = 0; i < 500 && g_atomic_int_get (&self->busy_workers) > 0; i++) {
        g_usleep (10 * 1000);
    }
}


/* ---- Password helpers ---- */

static void
pwd_changed_cb (GtkEditable *editable, gpointer user_data)
{
    Panel *p = user_data;
    static const gchar *labels[] = { N_("Very weak"), N_("Weak"), N_("Fair"),
                                     N_("Strong"), N_("Very strong") };
    const gchar *text = gtk_editable_get_text (editable);
    guint score = gtkcrypto_password_strength (text);
    gtk_level_bar_set_value (p->strength_bar, *text == '\0' ? 0 : score + 1);
    gtk_label_set_text (p->strength_label, *text == '\0' ? "" : _(labels[score]));
}

static void
generate_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    Panel *p = user_data;
    g_autofree gchar *pwd = gtkcrypto_password_generate (GENERATED_PWD_LEN);
    gtk_editable_set_text (GTK_EDITABLE (p->pwd_row), pwd);
    gtk_editable_set_text (GTK_EDITABLE (p->confirm_row), pwd);
    gtkcrypto_secure_clear (pwd, strlen (pwd));
    show_toast (p, _("Random password filled in: make sure you store it safely"));
}

static void
pwd_activated_cb (AdwEntryRow *row, gpointer user_data)
{
    (void)row;
    Panel *p = user_data;
    if (p->is_encrypt) {
        gtk_widget_grab_focus (GTK_WIDGET (p->confirm_row));
    } else {
        gtk_widget_activate (p->action_btn);
    }
}

static void
confirm_activated_cb (AdwEntryRow *row, gpointer user_data)
{
    (void)row;
    Panel *p = user_data;
    gtk_widget_activate (p->action_btn);
}


/* ---- Build UI ---- */

static GtkWidget *
build_panel (Panel *p)
{
    p->overlay = ADW_TOAST_OVERLAY (adw_toast_overlay_new ());

    GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top (page, 24);
    gtk_widget_set_margin_bottom (page, 24);
    gtk_widget_set_margin_start (page, 24);
    gtk_widget_set_margin_end (page, 24);

    GtkWidget *clamp = adw_clamp_new ();
    adw_clamp_set_maximum_size (ADW_CLAMP (clamp), 600);
    gtk_widget_set_vexpand (clamp, TRUE);

    GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 16);
    p->inputs_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 16);

    /* Files */
    p->files_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (p->files_group),
                                     p->is_encrypt ? _("Files to encrypt")
                                                   : _("Files to decrypt"));
    GtkWidget *header_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *add_btn = gtk_button_new_from_icon_name ("list-add-symbolic");
    gtk_widget_add_css_class (add_btn, "flat");
    set_a11y (add_btn, _("Add files"));
    g_signal_connect (add_btn, "clicked", G_CALLBACK (add_files_clicked_cb), p);
    p->clear_btn = gtk_button_new_from_icon_name ("edit-clear-all-symbolic");
    gtk_widget_add_css_class (p->clear_btn, "flat");
    set_a11y (p->clear_btn, _("Remove all files from the list"));
    g_signal_connect (p->clear_btn, "clicked", G_CALLBACK (clear_files_clicked_cb), p);
    gtk_box_append (GTK_BOX (header_box), add_btn);
    gtk_box_append (GTK_BOX (header_box), p->clear_btn);
    adw_preferences_group_set_header_suffix (ADW_PREFERENCES_GROUP (p->files_group),
                                             header_box);

    p->file_list = GTK_LIST_BOX (gtk_list_box_new ());
    gtk_list_box_set_selection_mode (p->file_list, GTK_SELECTION_NONE);
    gtk_widget_add_css_class (GTK_WIDGET (p->file_list), "boxed-list");
    GtkWidget *scroll = gtk_scrolled_window_new ();
    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
                                    GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_propagate_natural_height (GTK_SCROLLED_WINDOW (scroll), TRUE);
    gtk_scrolled_window_set_max_content_height (GTK_SCROLLED_WINDOW (scroll), 220);
    gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scroll),
                                   GTK_WIDGET (p->file_list));
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (p->files_group), scroll);
    attach_files_drop (p);
    panel_rebuild_rows (p);

    /* Encrypt-only: cipher information */
    GtkWidget *crypto_group = NULL;
    if (p->is_encrypt) {
        crypto_group = adw_preferences_group_new ();
        adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (crypto_group),
                                         _("Encryption Settings"));
        GtkWidget *cipher_row = adw_action_row_new ();
        adw_preferences_row_set_title (ADW_PREFERENCES_ROW (cipher_row), "AES-256-GCM");
        adw_action_row_set_subtitle (ADW_ACTION_ROW (cipher_row),
                                     _("Authenticated encryption"));
        adw_preferences_group_add (ADW_PREFERENCES_GROUP (crypto_group), cipher_row);
        GtkWidget *kdf_row = adw_action_row_new ();
        adw_preferences_row_set_title (ADW_PREFERENCES_ROW (kdf_row), "Argon2id");
        adw_action_row_set_subtitle (ADW_ACTION_ROW (kdf_row),
                                     _("Memory-hard password derivation"));
        adw_preferences_group_add (ADW_PREFERENCES_GROUP (crypto_group), kdf_row);
    }

    /* Password */
    GtkWidget *pwd_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (pwd_group), _("Password"));
    p->pwd_row = ADW_PASSWORD_ENTRY_ROW (adw_password_entry_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (p->pwd_row), _("Password"));
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (pwd_group), GTK_WIDGET (p->pwd_row));
    g_signal_connect (p->pwd_row, "entry-activated", G_CALLBACK (pwd_activated_cb), p);

    if (p->is_encrypt) {
        GtkWidget *gen_btn = gtk_button_new_from_icon_name ("view-refresh-symbolic");
        gtk_widget_set_valign (gen_btn, GTK_ALIGN_CENTER);
        gtk_widget_add_css_class (gen_btn, "flat");
        set_a11y (gen_btn, _("Generate a random password"));
        g_signal_connect (gen_btn, "clicked", G_CALLBACK (generate_clicked_cb), p);
        adw_entry_row_add_suffix (ADW_ENTRY_ROW (p->pwd_row), gen_btn);

        p->confirm_row = ADW_PASSWORD_ENTRY_ROW (adw_password_entry_row_new ());
        adw_preferences_row_set_title (ADW_PREFERENCES_ROW (p->confirm_row),
                                       _("Confirm Password"));
        adw_preferences_group_add (ADW_PREFERENCES_GROUP (pwd_group),
                                   GTK_WIDGET (p->confirm_row));
        g_signal_connect (p->confirm_row, "entry-activated",
                          G_CALLBACK (confirm_activated_cb), p);

        GtkWidget *strength_row = adw_action_row_new ();
        adw_preferences_row_set_title (ADW_PREFERENCES_ROW (strength_row), _("Strength"));
        p->strength_label = GTK_LABEL (gtk_label_new (""));
        gtk_widget_add_css_class (GTK_WIDGET (p->strength_label), "dim-label");
        p->strength_bar = GTK_LEVEL_BAR (gtk_level_bar_new_for_interval (0, 5));
        gtk_level_bar_set_mode (p->strength_bar, GTK_LEVEL_BAR_MODE_DISCRETE);
        gtk_level_bar_set_value (p->strength_bar, 0);
        gtk_level_bar_add_offset_value (p->strength_bar, GTK_LEVEL_BAR_OFFSET_LOW, 2);
        gtk_level_bar_add_offset_value (p->strength_bar, GTK_LEVEL_BAR_OFFSET_HIGH, 4);
        gtk_level_bar_add_offset_value (p->strength_bar, GTK_LEVEL_BAR_OFFSET_FULL, 5);
        gtk_widget_set_size_request (GTK_WIDGET (p->strength_bar), 120, -1);
        gtk_widget_set_valign (GTK_WIDGET (p->strength_bar), GTK_ALIGN_CENTER);
        adw_action_row_add_suffix (ADW_ACTION_ROW (strength_row), GTK_WIDGET (p->strength_label));
        adw_action_row_add_suffix (ADW_ACTION_ROW (strength_row), GTK_WIDGET (p->strength_bar));
        adw_preferences_group_add (ADW_PREFERENCES_GROUP (pwd_group), strength_row);
        g_signal_connect (p->pwd_row, "changed", G_CALLBACK (pwd_changed_cb), p);
    }

    /* Options */
    GtkWidget *opts_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (opts_group), _("Options"));

    p->output_row = ADW_ACTION_ROW (adw_action_row_new ());
    adw_preferences_row_set_use_markup (ADW_PREFERENCES_ROW (p->output_row), FALSE);
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (p->output_row), _("Output folder"));
    GtkWidget *folder_btn = gtk_button_new_from_icon_name ("folder-open-symbolic");
    gtk_widget_set_valign (folder_btn, GTK_ALIGN_CENTER);
    gtk_widget_add_css_class (folder_btn, "flat");
    set_a11y (folder_btn, _("Choose output folder"));
    g_signal_connect (folder_btn, "clicked", G_CALLBACK (choose_output_clicked_cb), p);
    p->output_reset_btn = gtk_button_new_from_icon_name ("edit-clear-symbolic");
    gtk_widget_set_valign (p->output_reset_btn, GTK_ALIGN_CENTER);
    gtk_widget_add_css_class (p->output_reset_btn, "flat");
    set_a11y (p->output_reset_btn, _("Use the folder of each original file"));
    g_signal_connect (p->output_reset_btn, "clicked", G_CALLBACK (reset_output_clicked_cb), p);
    adw_action_row_add_suffix (p->output_row, p->output_reset_btn);
    adw_action_row_add_suffix (p->output_row, folder_btn);
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (opts_group), GTK_WIDGET (p->output_row));
    panel_update_output_row (p);

    GtkWidget *delete_row = adw_action_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (delete_row),
                                   p->is_encrypt ? _("Delete original file after encryption")
                                                 : _("Delete encrypted file after decryption"));
    adw_action_row_set_subtitle (ADW_ACTION_ROW (delete_row),
                                 _("The file is unlinked, not securely erased"));
    p->delete_switch = GTK_SWITCH (gtk_switch_new ());
    gtk_widget_set_valign (GTK_WIDGET (p->delete_switch), GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (delete_row), GTK_WIDGET (p->delete_switch));
    adw_action_row_set_activatable_widget (ADW_ACTION_ROW (delete_row), GTK_WIDGET (p->delete_switch));
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (opts_group), delete_row);

    gtk_box_append (GTK_BOX (p->inputs_box), p->files_group);
    if (crypto_group != NULL) {
        gtk_box_append (GTK_BOX (p->inputs_box), crypto_group);
    }
    gtk_box_append (GTK_BOX (p->inputs_box), pwd_group);
    gtk_box_append (GTK_BOX (p->inputs_box), opts_group);

    /* Action row */
    GtkWidget *action_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign (action_box, GTK_ALIGN_CENTER);
    p->action_btn = gtk_button_new ();
    GtkWidget *btn_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append (GTK_BOX (btn_box), gtk_image_new_from_icon_name (
        p->is_encrypt ? "channel-secure-symbolic" : "channel-insecure-symbolic"));
    gtk_box_append (GTK_BOX (btn_box), gtk_label_new (
        p->is_encrypt ? _("Encrypt") : _("Decrypt")));
    gtk_button_set_child (GTK_BUTTON (p->action_btn), btn_box);
    gtk_widget_add_css_class (p->action_btn, "suggested-action");
    gtk_widget_add_css_class (p->action_btn, "pill");
    g_signal_connect (p->action_btn, "clicked", G_CALLBACK (action_clicked_cb), p);

    p->cancel_btn = gtk_button_new_with_label (_("Cancel"));
    gtk_widget_add_css_class (p->cancel_btn, "pill");
    gtk_widget_set_visible (p->cancel_btn, FALSE);
    g_signal_connect (p->cancel_btn, "clicked", G_CALLBACK (cancel_clicked_cb), p);
    gtk_box_append (GTK_BOX (action_box), p->action_btn);
    gtk_box_append (GTK_BOX (action_box), p->cancel_btn);

    p->progress = GTK_PROGRESS_BAR (gtk_progress_bar_new ());
    gtk_progress_bar_set_show_text (p->progress, TRUE);
    gtk_widget_set_visible (GTK_WIDGET (p->progress), FALSE);

    gtk_box_append (GTK_BOX (inner), p->inputs_box);
    gtk_box_append (GTK_BOX (inner), GTK_WIDGET (p->progress));
    gtk_box_append (GTK_BOX (inner), action_box);

    adw_clamp_set_child (ADW_CLAMP (clamp), inner);
    gtk_box_append (GTK_BOX (page), clamp);

    GtkWidget *scrolled = gtk_scrolled_window_new ();
    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled),
                                    GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scrolled), page);
    adw_toast_overlay_set_child (p->overlay, scrolled);
    return GTK_WIDGET (p->overlay);
}


static void
gtkcrypto_file_crypto_page_finalize (GObject *object)
{
    GtkcryptoFileCryptoPage *self = GTKCRYPTO_FILE_CRYPTO_PAGE (object);
    Panel *panels[] = { &self->enc, &self->dec };
    for (gsize i = 0; i < G_N_ELEMENTS (panels); i++) {
        g_slist_free_full (panels[i]->files, g_free);
        g_free (panels[i]->output_dir);
        g_clear_object (&panels[i]->cancellable);
    }
    G_OBJECT_CLASS (gtkcrypto_file_crypto_page_parent_class)->finalize (object);
}


static void
gtkcrypto_file_crypto_page_init (GtkcryptoFileCryptoPage *self)
{
    gtk_orientable_set_orientation (GTK_ORIENTABLE (self), GTK_ORIENTATION_VERTICAL);

    self->enc.page = self;
    self->enc.is_encrypt = TRUE;
    self->dec.page = self;
    self->dec.is_encrypt = FALSE;

    self->view_stack = ADW_VIEW_STACK (adw_view_stack_new ());

    GtkWidget *switcher = adw_view_switcher_new ();
    adw_view_switcher_set_stack (ADW_VIEW_SWITCHER (switcher), self->view_stack);
    adw_view_switcher_set_policy (ADW_VIEW_SWITCHER (switcher), ADW_VIEW_SWITCHER_POLICY_WIDE);
    gtk_widget_set_halign (switcher, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top (switcher, 8);

    GtkWidget *enc_page = build_panel (&self->enc);
    AdwViewStackPage *enc_vs_page = adw_view_stack_add_titled (self->view_stack, enc_page, "encrypt", _("Encrypt"));
    adw_view_stack_page_set_icon_name (enc_vs_page, "channel-secure-symbolic");

    GtkWidget *dec_page = build_panel (&self->dec);
    AdwViewStackPage *dec_vs_page = adw_view_stack_add_titled (self->view_stack, dec_page, "decrypt", _("Decrypt"));
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
