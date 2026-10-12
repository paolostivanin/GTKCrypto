#include <glib/gi18n.h>
#include <gcrypt.h>
#include "hashing-page.h"
#include "../hash.h"
#include "../crypt-common.h"
#include "../gtkcrypto.h"
#include "../state.h"

#define NUM_HASH_ALGOS 12

typedef struct {
    const gchar *label;
    gint         algo;
    gint         digest_size;
    gboolean     default_enabled;
} HashAlgoInfo;

static const HashAlgoInfo hash_algos[NUM_HASH_ALGOS] = {
    { "MD5 (insecure)",   GCRY_MD_MD5,           MD5_DIGEST_SIZE,         FALSE },
    { "SHA-1 (insecure)", GCRY_MD_SHA1,          SHA1_DIGEST_SIZE,        FALSE },
    { "GOST94",           GCRY_MD_GOSTR3411_94,  GOST94_DIGEST_SIZE,      FALSE },
    { "SHA-256",          GCRY_MD_SHA256,        SHA256_DIGEST_SIZE,      TRUE  },
    { "SHA3-256",         GCRY_MD_SHA3_256,      SHA3_256_DIGEST_SIZE,    TRUE  },
    { "BLAKE2b-256",      GCRY_MD_BLAKE2B_256,   BLAKE2B_256_DIGEST_SIZE, TRUE  },
    { "SHA-384",          GCRY_MD_SHA384,        SHA384_DIGEST_SIZE,      FALSE },
    { "SHA3-384",         GCRY_MD_SHA3_384,      SHA3_384_DIGEST_SIZE,    FALSE },
    { "SHA-512",          GCRY_MD_SHA512,        SHA512_DIGEST_SIZE,      TRUE  },
    { "SHA3-512",         GCRY_MD_SHA3_512,      SHA3_512_DIGEST_SIZE,    TRUE  },
    { "BLAKE2b-512",      GCRY_MD_BLAKE2B_512,   BLAKE2B_512_DIGEST_SIZE, TRUE  },
    { "WHIRLPOOL",        GCRY_MD_WHIRLPOOL,     WHIRLPOOL_DIGEST_SIZE,   FALSE },
};

/* Compare sub-page hash algorithms */
static const gchar *compare_algo_labels[] = {
    "MD5 (insecure)", "SHA-1 (insecure)", "SHA-256", "SHA-512", "SHA3-256", "SHA3-512",
    "BLAKE2b-256", "BLAKE2b-512", NULL,
};
static const gint compare_algo_ids[] = {
    GCRY_MD_MD5, GCRY_MD_SHA1, GCRY_MD_SHA256, GCRY_MD_SHA512, GCRY_MD_SHA3_256, GCRY_MD_SHA3_512,
    GCRY_MD_BLAKE2B_256, GCRY_MD_BLAKE2B_512,
};
static const gint compare_digest_sizes[] = {
    MD5_DIGEST_SIZE, SHA1_DIGEST_SIZE, SHA256_DIGEST_SIZE, SHA512_DIGEST_SIZE, SHA3_256_DIGEST_SIZE, SHA3_512_DIGEST_SIZE,
    BLAKE2B_256_DIGEST_SIZE, BLAKE2B_512_DIGEST_SIZE,
};

struct _GtkcryptoHashingPage {
    GtkBox parent_instance;

    AdwToastOverlay *toast_overlay;
    AdwViewStack    *view_stack;

    /* Compute sub-page */
    GtkLabel        *compute_file_label;
    gchar           *compute_filename;
    GtkWidget       *compute_drop_zone;
    GtkWidget       *expected_entry;
    gchar           *expected_hash;
    GtkWidget       *hash_rows[NUM_HASH_ALGOS];
    GtkWidget       *hash_switches[NUM_HASH_ALGOS];
    GtkWidget       *hash_result_labels[NUM_HASH_ALGOS];
    GtkWidget       *hash_spinners[NUM_HASH_ALGOS];
    GThreadPool     *compute_pool;
    GHashTable      *hash_cache;
    guint64          compute_generation;
    GCancellable    *compute_cancellable;

    /* Compare sub-page */
    GtkLabel        *file1_label;
    GtkLabel        *file2_label;
    gchar           *compare_file1;
    gchar           *compare_file2;
    GtkLabel        *compare_result_label;
    AdwComboRow     *compare_algo_row;
    GtkWidget       *compare_btn;
    GtkSpinner      *compare_spinner;
};

G_DEFINE_TYPE (GtkcryptoHashingPage, gtkcrypto_hashing_page, GTK_TYPE_BOX)

static void
set_a11y (GtkWidget *widget, const gchar *label)
{
    gtk_widget_set_tooltip_text (widget, label);
    gtk_accessible_update_property (GTK_ACCESSIBLE (widget),
                                    GTK_ACCESSIBLE_PROPERTY_LABEL, label, -1);
}


typedef struct {
    GtkcryptoHashingPage *page;
    gchar                *filename;
    gint                  indices[NUM_HASH_ALGOS];
    guint                 n_algos;
    guint64               generation;
    GCancellable         *cancellable;
} ComputeThreadData;

typedef struct {
    GtkcryptoHashingPage *page;
    gchar *file1;
    gchar *file2;
    gint algo;
    gint digest;
    gchar *hash1;
    gchar *hash2;
} CompareThreadData;


/* ---- Toast helper ---- */

static void
hashing_page_show_toast (GtkcryptoHashingPage *self, const gchar *msg)
{
    if (self->toast_overlay == NULL) return;
    AdwToast *t = adw_toast_new (msg);
    adw_toast_set_timeout (t, 2);
    adw_toast_overlay_add_toast (self->toast_overlay, t);
}


/* ---- Expected-hash matching ---- */

static void
update_expected_match (GtkcryptoHashingPage *self)
{
    gboolean has_expected = self->expected_hash && *self->expected_hash;
    for (gint i = 0; i < NUM_HASH_ALGOS; i++) {
        const gchar *cur = gtk_label_get_text (GTK_LABEL (self->hash_result_labels[i]));
        gboolean match = has_expected && cur && *cur && g_ascii_strcasecmp (cur, self->expected_hash) == 0;
        if (match) {
            gtk_widget_add_css_class (self->hash_rows[i], "hash-match");
        } else {
            gtk_widget_remove_css_class (self->hash_rows[i], "hash-match");
        }
    }
}


static void
expected_entry_changed_cb (GtkEditable *editable, gpointer user_data)
{
    GtkcryptoHashingPage *self = user_data;
    const gchar *raw = gtk_editable_get_text (editable);
    g_free (self->expected_hash);

    /* Strip whitespace and lowercase. */
    g_autofree gchar *stripped = g_strdup (raw ? raw : "");
    g_strstrip (stripped);
    self->expected_hash = g_ascii_strdown (stripped, -1);

    update_expected_match (self);
}


/* ---- Compute hash thread ---- */

typedef struct {
    GtkcryptoHashingPage *page;
    gint                  algo_index;
    gchar                *hash;
    guint64               generation;
} HashDoneData;

static gboolean
hash_done_idle (gpointer user_data)
{
    HashDoneData *hd = user_data;

    if (hd->generation != hd->page->compute_generation) {
        g_object_unref (hd->page);
        g_free (hd->hash);
        g_free (hd);
        return G_SOURCE_REMOVE;
    }

    if (!gtk_switch_get_active (GTK_SWITCH (hd->page->hash_switches[hd->algo_index]))) {
        /* Switched off while computing: discard the result. */
        gtk_spinner_stop (GTK_SPINNER (hd->page->hash_spinners[hd->algo_index]));
        g_object_unref (hd->page);
        g_free (hd->hash);
        g_free (hd);
        return G_SOURCE_REMOVE;
    }

    if (hd->hash) {
        gtk_label_set_text (GTK_LABEL (hd->page->hash_result_labels[hd->algo_index]), hd->hash);
        g_hash_table_insert (hd->page->hash_cache,
                             g_strdup (hash_algos[hd->algo_index].label),
                             g_strdup (hd->hash));
    } else {
        gtk_label_set_text (GTK_LABEL (hd->page->hash_result_labels[hd->algo_index]), _("Error"));
        g_autofree gchar *msg = g_strdup_printf (_("Failed to compute %s hash"),
                                                 hash_algos[hd->algo_index].label);
        hashing_page_show_toast (hd->page, msg);
    }

    gtk_spinner_stop (GTK_SPINNER (hd->page->hash_spinners[hd->algo_index]));
    update_expected_match (hd->page);

    g_free (hd->hash);
    g_object_unref (hd->page);
    g_free (hd);
    return G_SOURCE_REMOVE;
}

static void
compute_hash_thread (gpointer data, gpointer user_data)
{
    (void)user_data;
    ComputeThreadData *td = data;

    gint algos[NUM_HASH_ALGOS];
    gint sizes[NUM_HASH_ALGOS];
    gchar *hex[NUM_HASH_ALGOS];
    for (guint i = 0; i < td->n_algos; i++) {
        algos[i] = hash_algos[td->indices[i]].algo;
        sizes[i] = hash_algos[td->indices[i]].digest_size;
    }

    /* A single pass over the file feeds every requested algorithm. */
    g_autoptr(GError) error = NULL;
    gboolean ok = gtkcrypto_hash_file (td->filename, algos, sizes,
                                       td->n_algos, td->cancellable, hex,
                                       &error);
    gboolean cancelled = !ok && g_error_matches (error, GTKCRYPTO_ERROR,
                                                 GTKCRYPTO_ERROR_CANCELLED);

    /* Cancelled work belongs to a stale generation; the page already reset
     * its rows, so there is nothing to report. */
    if (!cancelled) {
        for (guint i = 0; i < td->n_algos; i++) {
            HashDoneData *hd = g_new0 (HashDoneData, 1);
            hd->page = g_object_ref (td->page);
            hd->algo_index = td->indices[i];
            hd->hash = ok ? hex[i] : NULL;
            hd->generation = td->generation;
            g_idle_add (hash_done_idle, hd);
        }
    }

    g_object_unref (td->page);
    g_object_unref (td->cancellable);
    g_free (td->filename);
    g_free (td);
}


static void
start_compute_for_indices (GtkcryptoHashingPage *self,
                           const gint *indices, guint n)
{
    if (self->compute_filename == NULL) return;

    ComputeThreadData *td = g_new0 (ComputeThreadData, 1);
    td->page = g_object_ref (self);
    td->filename = g_strdup (self->compute_filename);
    td->generation = self->compute_generation;
    if (self->compute_cancellable == NULL) {
        self->compute_cancellable = g_cancellable_new ();
    }
    td->cancellable = g_object_ref (self->compute_cancellable);

    for (guint i = 0; i < n; i++) {
        gint idx = indices[i];
        /* Cache hit -> just paint the result. */
        gpointer cached = g_hash_table_lookup (self->hash_cache,
                                               hash_algos[idx].label);
        if (cached) {
            gtk_label_set_text (GTK_LABEL (self->hash_result_labels[idx]), cached);
            update_expected_match (self);
            continue;
        }
        gtk_spinner_start (GTK_SPINNER (self->hash_spinners[idx]));
        td->indices[td->n_algos++] = idx;
    }

    if (td->n_algos == 0) {
        g_object_unref (td->page);
        g_object_unref (td->cancellable);
        g_free (td->filename);
        g_free (td);
        return;
    }
    g_thread_pool_push (self->compute_pool, td, NULL);
}


static void
start_compute_for_index (GtkcryptoHashingPage *self, gint idx)
{
    if (idx < 0 || idx >= NUM_HASH_ALGOS) return;
    start_compute_for_indices (self, &idx, 1);
}


static void
start_all_enabled_computes (GtkcryptoHashingPage *self)
{
    gint indices[NUM_HASH_ALGOS];
    guint n = 0;
    for (gint i = 0; i < NUM_HASH_ALGOS; i++) {
        if (gtk_switch_get_active (GTK_SWITCH (self->hash_switches[i]))) {
            indices[n++] = i;
        }
    }
    if (n > 0) {
        start_compute_for_indices (self, indices, n);
    }
}


static void
hash_switch_toggled_cb (GObject *obj, GParamSpec *pspec, gpointer user_data)
{
    (void)pspec;
    GtkcryptoHashingPage *self = user_data;
    GtkSwitch *sw = GTK_SWITCH (obj);
    gboolean active = gtk_switch_get_active (sw);

    gint idx = -1;
    for (gint i = 0; i < NUM_HASH_ALGOS; i++) {
        if (GTK_WIDGET (sw) == self->hash_switches[i]) {
            idx = i;
            break;
        }
    }
    if (idx < 0) return;

    state_set_hash_enabled (hash_algos[idx].label, active);

    if (!active) {
        gtk_label_set_text (GTK_LABEL (self->hash_result_labels[idx]), "");
        update_expected_match (self);
        return;
    }

    start_compute_for_index (self, idx);
}


/* ---- Compute file ingest ---- */

static void
set_compute_file (GtkcryptoHashingPage *self, gchar *path /* takes ownership */)
{
    if (path == NULL) {
        return;  /* non-local file: no path to hash */
    }
    g_free (self->compute_filename);
    self->compute_filename = path;
    self->compute_generation++;

    /* Abort hashing of the previous file and start a fresh cancellable. */
    if (self->compute_cancellable != NULL) {
        g_cancellable_cancel (self->compute_cancellable);
        g_clear_object (&self->compute_cancellable);
    }

    g_autofree gchar *basename = g_path_get_basename (self->compute_filename);
    gtk_label_set_text (self->compute_file_label, basename);

    /* Clear cache and per-row results, but preserve switch state. */
    g_hash_table_remove_all (self->hash_cache);
    for (gint i = 0; i < NUM_HASH_ALGOS; i++) {
        gtk_label_set_text (GTK_LABEL (self->hash_result_labels[i]), "");
        gtk_spinner_stop (GTK_SPINNER (self->hash_spinners[i]));
        gtk_widget_remove_css_class (self->hash_rows[i], "hash-match");
    }

    /* Clear expected-hash field — different file usually means different expectation. */
    if (self->expected_entry) {
        g_signal_handlers_block_by_func (self->expected_entry,
                                         (gpointer) expected_entry_changed_cb, self);
        gtk_editable_set_text (GTK_EDITABLE (self->expected_entry), "");
        g_signal_handlers_unblock_by_func (self->expected_entry,
                                           (gpointer) expected_entry_changed_cb, self);
    }
    g_free (self->expected_hash);
    self->expected_hash = NULL;

    start_all_enabled_computes (self);
}


/* ---- File chooser callbacks ---- */

static void
compute_file_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoHashingPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GFile) file = gtk_file_dialog_open_finish (dialog, result, NULL);
    if (file == NULL) return;

    set_compute_file (self, g_file_get_path (file));
}


static void
compute_choose_file_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoHashingPage *self = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, _("Choose file to hash"));
    GtkWidget *toplevel = GTK_WIDGET (gtk_widget_get_root (GTK_WIDGET (self)));
    gtk_file_dialog_open (dialog, GTK_WINDOW (toplevel), NULL,
                          compute_file_chosen_cb, self);
}


/* ---- Drag and drop ---- */

static GdkDragAction
drop_enter_highlight_cb (GtkDropTarget *target, double x, double y, gpointer user_data)
{
    (void)target; (void)x; (void)y;
    gtk_widget_add_css_class (GTK_WIDGET (user_data), "drop-target-active");
    return GDK_ACTION_COPY;
}

static void
drop_leave_unhighlight_cb (GtkDropTarget *target, gpointer user_data)
{
    (void)target;
    gtk_widget_remove_css_class (GTK_WIDGET (user_data), "drop-target-active");
}

static gboolean
compute_drop_cb (GtkDropTarget *target, const GValue *value, double x, double y, gpointer user_data)
{
    (void)target; (void)x; (void)y;
    if (!G_VALUE_HOLDS (value, G_TYPE_FILE)) return FALSE;

    GFile *file = g_value_get_object (value);
    if (file == NULL) return FALSE;

    GtkcryptoHashingPage *self = user_data;
    set_compute_file (self, g_file_get_path (file));
    return TRUE;
}


/* ---- Copy hash to clipboard ---- */

static void
copy_hash_clicked_cb (GtkButton *btn, gpointer user_data)
{
    GtkcryptoHashingPage *self = g_object_get_data (G_OBJECT (btn), "page");
    GtkLabel *label = GTK_LABEL (user_data);
    const gchar *text = gtk_label_get_text (label);
    if (text && *text) {
        GdkClipboard *clipboard = gdk_display_get_clipboard (
            gdk_display_get_default ());
        gdk_clipboard_set_text (clipboard, text);
        if (self) hashing_page_show_toast (self, _("Hash copied to clipboard"));
    }
}


/* ---- Compare sub-page ---- */

static void
set_compare_file1 (GtkcryptoHashingPage *self, gchar *path)
{
    if (path == NULL) {
        return;
    }
    g_free (self->compare_file1);
    self->compare_file1 = path;
    g_autofree gchar *basename = g_path_get_basename (self->compare_file1);
    gtk_label_set_text (self->file1_label, basename);
}


static void
set_compare_file2 (GtkcryptoHashingPage *self, gchar *path)
{
    if (path == NULL) {
        return;
    }
    g_free (self->compare_file2);
    self->compare_file2 = path;
    g_autofree gchar *basename = g_path_get_basename (self->compare_file2);
    gtk_label_set_text (self->file2_label, basename);
}


static void
compare_file1_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoHashingPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GFile) file = gtk_file_dialog_open_finish (dialog, result, NULL);
    if (file == NULL) return;
    set_compare_file1 (self, g_file_get_path (file));
}

static void
compare_file2_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoHashingPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GFile) file = gtk_file_dialog_open_finish (dialog, result, NULL);
    if (file == NULL) return;
    set_compare_file2 (self, g_file_get_path (file));
}

static void
compare_choose_file1_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoHashingPage *self = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, _("Choose first file"));
    GtkWidget *toplevel = GTK_WIDGET (gtk_widget_get_root (GTK_WIDGET (self)));
    gtk_file_dialog_open (dialog, GTK_WINDOW (toplevel), NULL,
                          compare_file1_chosen_cb, self);
}

static void
compare_choose_file2_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoHashingPage *self = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, _("Choose second file"));
    GtkWidget *toplevel = GTK_WIDGET (gtk_widget_get_root (GTK_WIDGET (self)));
    gtk_file_dialog_open (dialog, GTK_WINDOW (toplevel), NULL,
                          compare_file2_chosen_cb, self);
}


static gboolean
compare_file1_drop_cb (GtkDropTarget *target, const GValue *value, double x, double y, gpointer user_data)
{
    (void)target; (void)x; (void)y;
    if (!G_VALUE_HOLDS (value, G_TYPE_FILE)) return FALSE;
    GFile *file = g_value_get_object (value);
    if (file == NULL) return FALSE;
    set_compare_file1 (user_data, g_file_get_path (file));
    return TRUE;
}

static gboolean
compare_file2_drop_cb (GtkDropTarget *target, const GValue *value, double x, double y, gpointer user_data)
{
    (void)target; (void)x; (void)y;
    if (!G_VALUE_HOLDS (value, G_TYPE_FILE)) return FALSE;
    GFile *file = g_value_get_object (value);
    if (file == NULL) return FALSE;
    set_compare_file2 (user_data, g_file_get_path (file));
    return TRUE;
}


static gboolean
compare_result_idle (gpointer user_data)
{
    CompareThreadData *cd = user_data;

    gtk_spinner_stop (cd->page->compare_spinner);
    gtk_widget_set_sensitive (cd->page->compare_btn, TRUE);

    if (cd->hash1 == NULL || cd->hash2 == NULL) {
        gtk_label_set_text (cd->page->compare_result_label, _("Error computing hash"));
        gtk_widget_remove_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-match");
        gtk_widget_add_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-mismatch");
    } else if (g_strcmp0 (cd->hash1, cd->hash2) == 0) {
        gtk_label_set_text (cd->page->compare_result_label, _("Hashes match"));
        gtk_widget_remove_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-mismatch");
        gtk_widget_add_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-match");
    } else {
        gtk_label_set_text (cd->page->compare_result_label, _("Hashes do NOT match"));
        gtk_widget_remove_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-match");
        gtk_widget_add_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-mismatch");
    }

    g_free (cd->hash1);
    g_free (cd->hash2);
    g_free (cd->file1);
    g_free (cd->file2);
    g_object_unref (cd->page);
    g_free (cd);
    return G_SOURCE_REMOVE;
}


static gpointer
compare_thread_func (gpointer user_data)
{
    CompareThreadData *cd = user_data;
    cd->hash1 = get_file_hash (cd->file1, cd->algo, cd->digest);
    cd->hash2 = get_file_hash (cd->file2, cd->algo, cd->digest);

    g_idle_add (compare_result_idle, cd);
    return NULL;
}


static void
compare_btn_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoHashingPage *self = user_data;

    if (self->compare_file1 == NULL || self->compare_file2 == NULL) {
        gtk_label_set_text (self->compare_result_label, _("Please select both files first"));
        return;
    }

    gtk_widget_set_sensitive (self->compare_btn, FALSE);
    gtk_spinner_start (self->compare_spinner);
    gtk_label_set_text (self->compare_result_label, "Computing...");

    CompareThreadData *cd = g_new0 (CompareThreadData, 1);
    cd->page = g_object_ref (self);
    cd->file1 = g_strdup (self->compare_file1);
    cd->file2 = g_strdup (self->compare_file2);
    guint selected = adw_combo_row_get_selected (self->compare_algo_row);
    cd->algo = compare_algo_ids[selected];
    cd->digest = compare_digest_sizes[selected];
    g_thread_unref (g_thread_new ("compare-hash", compare_thread_func, cd));
}


/* ---- DnD attachment helper ---- */

static void
attach_single_file_drop (GtkWidget *target_widget,
                         GCallback  drop_cb,
                         gpointer   user_data)
{
    GtkDropTarget *target = gtk_drop_target_new (G_TYPE_FILE, GDK_ACTION_COPY);
    g_signal_connect (target, "drop", drop_cb, user_data);
    g_signal_connect (target, "enter", G_CALLBACK (drop_enter_highlight_cb), target_widget);
    g_signal_connect (target, "leave", G_CALLBACK (drop_leave_unhighlight_cb), target_widget);
    gtk_widget_add_controller (target_widget, GTK_EVENT_CONTROLLER (target));
}


/* ---- Build UI ---- */

static GtkWidget *
build_compute_page (GtkcryptoHashingPage *self)
{
    GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top (page, 24);
    gtk_widget_set_margin_bottom (page, 24);
    gtk_widget_set_margin_start (page, 24);
    gtk_widget_set_margin_end (page, 24);

    /* File chooser row */
    GtkWidget *file_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    self->compute_drop_zone = file_box;
    GtkWidget *file_btn = gtk_button_new_with_label (_("Choose File"));
    gtk_widget_add_css_class (file_btn, "suggested-action");
    self->compute_file_label = GTK_LABEL (gtk_label_new (_("No file selected — or drop one here")));
    gtk_label_set_ellipsize (self->compute_file_label, PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_set_hexpand (GTK_WIDGET (self->compute_file_label), TRUE);
    gtk_box_append (GTK_BOX (file_box), file_btn);
    gtk_box_append (GTK_BOX (file_box), GTK_WIDGET (self->compute_file_label));
    gtk_box_append (GTK_BOX (page), file_box);
    g_signal_connect (file_btn, "clicked", G_CALLBACK (compute_choose_file_cb), self);
    attach_single_file_drop (file_box, G_CALLBACK (compute_drop_cb), self);

    /* Verify-against expected hash */
    GtkWidget *verify_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (verify_group), _("Verify Against"));
    adw_preferences_group_set_description (ADW_PREFERENCES_GROUP (verify_group),
                                           _("Paste an expected hash to highlight the matching row"));
    self->expected_entry = adw_entry_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->expected_entry), _("Expected hash"));
    g_signal_connect (self->expected_entry, "changed",
                      G_CALLBACK (expected_entry_changed_cb), self);
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (verify_group), self->expected_entry);

    /* Hash algorithm list */
    GtkWidget *prefs_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (prefs_group), _("Hash Algorithms"));
    adw_preferences_group_set_description (ADW_PREFERENCES_GROUP (prefs_group),
                                           _("Toggle algorithms to compute their hash"));

    for (gint i = 0; i < NUM_HASH_ALGOS; i++) {
        GtkWidget *row = adw_action_row_new ();
        adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row), hash_algos[i].label);
        self->hash_rows[i] = row;

        /* Switch to enable/disable */
        GtkWidget *sw = gtk_switch_new ();
        gtk_widget_set_valign (sw, GTK_ALIGN_CENTER);
        self->hash_switches[i] = sw;
        adw_action_row_add_prefix (ADW_ACTION_ROW (row), sw);

        /* Restore persisted state BEFORE wiring the signal so we don't trigger
           a compute attempt with no file selected. */
        gboolean enabled = state_get_hash_enabled (hash_algos[i].label,
                                                    hash_algos[i].default_enabled);
        gtk_switch_set_active (GTK_SWITCH (sw), enabled);

        g_signal_connect (sw, "notify::active", G_CALLBACK (hash_switch_toggled_cb), self);

        /* Spinner */
        GtkWidget *spinner = gtk_spinner_new ();
        self->hash_spinners[i] = spinner;
        adw_action_row_add_suffix (ADW_ACTION_ROW (row), spinner);

        /* Result label */
        GtkWidget *result_label = gtk_label_new ("");
        gtk_label_set_selectable (GTK_LABEL (result_label), TRUE);
        gtk_widget_add_css_class (result_label, "hash-result");
        gtk_label_set_ellipsize (GTK_LABEL (result_label), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand (result_label, TRUE);
        gtk_label_set_xalign (GTK_LABEL (result_label), 0.0f);
        self->hash_result_labels[i] = result_label;
        adw_action_row_add_suffix (ADW_ACTION_ROW (row), result_label);

        /* Copy button */
        GtkWidget *copy_btn = gtk_button_new_from_icon_name ("edit-copy-symbolic");
    set_a11y (copy_btn, _("Copy hash"));
        gtk_widget_set_valign (copy_btn, GTK_ALIGN_CENTER);
        gtk_widget_add_css_class (copy_btn, "flat");
        gtk_widget_set_tooltip_text (copy_btn, _("Copy to clipboard"));
        g_object_set_data (G_OBJECT (copy_btn), "page", self);
        adw_action_row_add_suffix (ADW_ACTION_ROW (row), copy_btn);
        g_signal_connect (copy_btn, "clicked", G_CALLBACK (copy_hash_clicked_cb), result_label);

        adw_preferences_group_add (ADW_PREFERENCES_GROUP (prefs_group), row);
    }

    GtkWidget *scroll = gtk_scrolled_window_new ();
    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
                                    GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand (scroll, TRUE);

    GtkWidget *clamp = adw_clamp_new ();
    GtkWidget *clamp_inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 16);
    gtk_box_append (GTK_BOX (clamp_inner), verify_group);
    gtk_box_append (GTK_BOX (clamp_inner), prefs_group);
    adw_clamp_set_child (ADW_CLAMP (clamp), clamp_inner);
    adw_clamp_set_maximum_size (ADW_CLAMP (clamp), 900);
    gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scroll), clamp);
    gtk_box_append (GTK_BOX (page), scroll);

    return page;
}


static GtkWidget *
build_compare_page (GtkcryptoHashingPage *self)
{
    GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top (page, 24);
    gtk_widget_set_margin_bottom (page, 24);
    gtk_widget_set_margin_start (page, 24);
    gtk_widget_set_margin_end (page, 24);

    GtkWidget *clamp = adw_clamp_new ();
    adw_clamp_set_maximum_size (ADW_CLAMP (clamp), 700);
    gtk_widget_set_vexpand (clamp, TRUE);

    GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 16);

    /* File 1 */
    GtkWidget *prefs1 = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (prefs1), _("First File"));
    GtkWidget *file1_row = adw_action_row_new ();
    self->file1_label = GTK_LABEL (gtk_label_new (_("No file selected — or drop one here")));
    gtk_label_set_ellipsize (self->file1_label, PANGO_ELLIPSIZE_MIDDLE);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file1_row), GTK_WIDGET (self->file1_label));
    GtkWidget *file1_btn = gtk_button_new_from_icon_name ("document-open-symbolic");
    set_a11y (file1_btn, _("Choose first file"));
    gtk_widget_set_valign (file1_btn, GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file1_row), file1_btn);
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (file1_row), _("File"));
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (prefs1), file1_row);
    g_signal_connect (file1_btn, "clicked", G_CALLBACK (compare_choose_file1_cb), self);
    attach_single_file_drop (file1_row, G_CALLBACK (compare_file1_drop_cb), self);

    /* File 2 */
    GtkWidget *prefs2 = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (prefs2), _("Second File"));
    GtkWidget *file2_row = adw_action_row_new ();
    self->file2_label = GTK_LABEL (gtk_label_new (_("No file selected — or drop one here")));
    gtk_label_set_ellipsize (self->file2_label, PANGO_ELLIPSIZE_MIDDLE);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file2_row), GTK_WIDGET (self->file2_label));
    GtkWidget *file2_btn = gtk_button_new_from_icon_name ("document-open-symbolic");
    set_a11y (file2_btn, _("Choose second file"));
    gtk_widget_set_valign (file2_btn, GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file2_row), file2_btn);
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (file2_row), _("File"));
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (prefs2), file2_row);
    g_signal_connect (file2_btn, "clicked", G_CALLBACK (compare_choose_file2_cb), self);
    attach_single_file_drop (file2_row, G_CALLBACK (compare_file2_drop_cb), self);

    /* Algorithm selection */
    GtkWidget *algo_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (algo_group), _("Algorithm"));
    self->compare_algo_row = ADW_COMBO_ROW (adw_combo_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->compare_algo_row), _("Hash Algorithm"));
    GtkStringList *algo_list = gtk_string_list_new (compare_algo_labels);
    adw_combo_row_set_model (self->compare_algo_row, G_LIST_MODEL (algo_list));
    adw_combo_row_set_selected (self->compare_algo_row, 3); /* SHA-512 default */
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (algo_group),
                               GTK_WIDGET (self->compare_algo_row));

    /* Compare button & result */
    GtkWidget *action_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign (action_box, GTK_ALIGN_CENTER);
    self->compare_btn = gtk_button_new_with_label (_("Compare"));
    gtk_widget_add_css_class (self->compare_btn, "suggested-action");
    gtk_widget_add_css_class (self->compare_btn, "pill");
    self->compare_spinner = GTK_SPINNER (gtk_spinner_new ());
    gtk_box_append (GTK_BOX (action_box), self->compare_btn);
    gtk_box_append (GTK_BOX (action_box), GTK_WIDGET (self->compare_spinner));
    g_signal_connect (self->compare_btn, "clicked", G_CALLBACK (compare_btn_clicked_cb), self);

    self->compare_result_label = GTK_LABEL (gtk_label_new (""));
    gtk_widget_set_halign (GTK_WIDGET (self->compare_result_label), GTK_ALIGN_CENTER);

    gtk_box_append (GTK_BOX (inner), prefs1);
    gtk_box_append (GTK_BOX (inner), prefs2);
    gtk_box_append (GTK_BOX (inner), algo_group);
    gtk_box_append (GTK_BOX (inner), action_box);
    gtk_box_append (GTK_BOX (inner), GTK_WIDGET (self->compare_result_label));

    adw_clamp_set_child (ADW_CLAMP (clamp), inner);
    gtk_box_append (GTK_BOX (page), clamp);

    return page;
}


static void
gtkcrypto_hashing_page_finalize (GObject *object)
{
    GtkcryptoHashingPage *self = GTKCRYPTO_HASHING_PAGE (object);

    g_free (self->compute_filename);
    g_free (self->compare_file1);
    g_free (self->compare_file2);
    g_free (self->expected_hash);
    if (self->compute_cancellable != NULL) {
        g_cancellable_cancel (self->compute_cancellable);
        g_clear_object (&self->compute_cancellable);
    }
    if (self->compute_pool)
        g_thread_pool_free (self->compute_pool, FALSE, FALSE);
    if (self->hash_cache)
        g_hash_table_unref (self->hash_cache);

    G_OBJECT_CLASS (gtkcrypto_hashing_page_parent_class)->finalize (object);
}


static void
gtkcrypto_hashing_page_init (GtkcryptoHashingPage *self)
{
    gtk_orientable_set_orientation (GTK_ORIENTABLE (self), GTK_ORIENTATION_VERTICAL);

    self->compute_pool = g_thread_pool_new (compute_hash_thread, NULL,
                                             (gint)g_get_num_processors (), FALSE, NULL);
    self->hash_cache = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

    self->view_stack = ADW_VIEW_STACK (adw_view_stack_new ());

    GtkWidget *switcher_bar = adw_view_switcher_new ();
    adw_view_switcher_set_stack (ADW_VIEW_SWITCHER (switcher_bar), self->view_stack);
    adw_view_switcher_set_policy (ADW_VIEW_SWITCHER (switcher_bar), ADW_VIEW_SWITCHER_POLICY_WIDE);
    gtk_widget_set_halign (switcher_bar, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top (switcher_bar, 8);

    GtkWidget *compute_page = build_compute_page (self);
    AdwViewStackPage *cp = adw_view_stack_add_titled (self->view_stack, compute_page, "compute", _("Compute"));
    adw_view_stack_page_set_icon_name (cp, "accessories-calculator-symbolic");

    GtkWidget *compare_page = build_compare_page (self);
    AdwViewStackPage *cmp = adw_view_stack_add_titled (self->view_stack, compare_page, "compare", _("Compare"));
    adw_view_stack_page_set_icon_name (cmp, "view-dual-symbolic");

    self->toast_overlay = ADW_TOAST_OVERLAY (adw_toast_overlay_new ());
    adw_toast_overlay_set_child (self->toast_overlay, GTK_WIDGET (self->view_stack));
    gtk_widget_set_vexpand (GTK_WIDGET (self->toast_overlay), TRUE);

    gtk_box_append (GTK_BOX (self), switcher_bar);
    gtk_box_append (GTK_BOX (self), GTK_WIDGET (self->toast_overlay));
}


static void
gtkcrypto_hashing_page_class_init (GtkcryptoHashingPageClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    object_class->finalize = gtkcrypto_hashing_page_finalize;
}


GtkcryptoHashingPage *
gtkcrypto_hashing_page_new (void)
{
    return g_object_new (GTKCRYPTO_TYPE_HASHING_PAGE, NULL);
}
