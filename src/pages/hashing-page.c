#include <gcrypt.h>
#include "hashing-page.h"
#include "../hash.h"
#include "../gtkcrypto.h"

#define NUM_HASH_ALGOS 12

typedef struct {
    const gchar *label;
    gint         algo;
    gint         digest_size;
} HashAlgoInfo;

static const HashAlgoInfo hash_algos[NUM_HASH_ALGOS] = {
    { "MD5 (insecure)",  GCRY_MD_MD5,          MD5_DIGEST_SIZE },
    { "SHA-1 (insecure)", GCRY_MD_SHA1,         SHA1_DIGEST_SIZE },
    { "GOST94",          GCRY_MD_GOSTR3411_94,  GOST94_DIGEST_SIZE },
    { "SHA-256",         GCRY_MD_SHA256,        SHA256_DIGEST_SIZE },
    { "SHA3-256",        GCRY_MD_SHA3_256,      SHA3_256_DIGEST_SIZE },
    { "BLAKE2b-256",     GCRY_MD_BLAKE2B_256,   BLAKE2B_256_DIGEST_SIZE },
    { "SHA-384",         GCRY_MD_SHA384,        SHA384_DIGEST_SIZE },
    { "SHA3-384",        GCRY_MD_SHA3_384,      SHA3_384_DIGEST_SIZE },
    { "SHA-512",         GCRY_MD_SHA512,        SHA512_DIGEST_SIZE },
    { "SHA3-512",        GCRY_MD_SHA3_512,      SHA3_512_DIGEST_SIZE },
    { "BLAKE2b-512",     GCRY_MD_BLAKE2B_512,   BLAKE2B_512_DIGEST_SIZE },
    { "WHIRLPOOL",       GCRY_MD_WHIRLPOOL,     WHIRLPOOL_DIGEST_SIZE },
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

    /* Compute sub-page */
    AdwViewStack    *view_stack;
    GtkLabel        *compute_file_label;
    gchar           *compute_filename;
    GtkWidget       *hash_rows[NUM_HASH_ALGOS];
    GtkWidget       *hash_switches[NUM_HASH_ALGOS];
    GtkWidget       *hash_result_labels[NUM_HASH_ALGOS];
    GtkWidget       *hash_spinners[NUM_HASH_ALGOS];
    GThreadPool     *compute_pool;
    GHashTable      *hash_cache;

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

typedef struct {
    GtkcryptoHashingPage *page;
    gint                  algo_index;
    gchar                *filename;
    gint                  hash_algo;
    gint                  digest_size;
} ComputeThreadData;

typedef struct {
    GtkcryptoHashingPage *page;
    gchar *hash1;
    gchar *hash2;
} CompareThreadData;


/* ---- Compute hash thread ---- */

typedef struct {
    GtkcryptoHashingPage *page;
    gint                  algo_index;
    gchar                *hash;
} HashDoneData;

static gboolean
hash_done_idle (gpointer user_data)
{
    HashDoneData *hd = user_data;

    if (hd->hash) {
        gtk_label_set_text (GTK_LABEL (hd->page->hash_result_labels[hd->algo_index]), hd->hash);
        g_hash_table_insert (hd->page->hash_cache,
                             g_strdup (hash_algos[hd->algo_index].label),
                             g_strdup (hd->hash));
    } else {
        gtk_label_set_text (GTK_LABEL (hd->page->hash_result_labels[hd->algo_index]), "Error");
    }

    gtk_spinner_stop (GTK_SPINNER (hd->page->hash_spinners[hd->algo_index]));

    g_free (hd->hash);
    g_free (hd);
    return G_SOURCE_REMOVE;
}

static void
compute_hash_thread (gpointer data, gpointer user_data)
{
    (void)user_data;
    ComputeThreadData *td = data;

    gchar *hash = get_file_hash (td->filename, td->hash_algo, td->digest_size);

    HashDoneData *hd = g_new0 (HashDoneData, 1);
    hd->page = td->page;
    hd->algo_index = td->algo_index;
    hd->hash = hash;
    g_idle_add (hash_done_idle, hd);

    g_free (td->filename);
    g_free (td);
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

    if (!active) {
        gtk_label_set_text (GTK_LABEL (self->hash_result_labels[idx]), "");
        return;
    }

    if (self->compute_filename == NULL) return;

    /* Check cache */
    gpointer cached = g_hash_table_lookup (self->hash_cache, hash_algos[idx].label);
    if (cached) {
        gtk_label_set_text (GTK_LABEL (self->hash_result_labels[idx]), cached);
        return;
    }

    /* Start spinner and compute */
    gtk_spinner_start (GTK_SPINNER (self->hash_spinners[idx]));

    ComputeThreadData *td = g_new0 (ComputeThreadData, 1);
    td->page = self;
    td->algo_index = idx;
    td->filename = g_strdup (self->compute_filename);
    td->hash_algo = hash_algos[idx].algo;
    td->digest_size = hash_algos[idx].digest_size;

    g_thread_pool_push (self->compute_pool, td, NULL);
}


/* ---- File chooser callbacks ---- */

static void
compute_file_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoHashingPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GFile) file = gtk_file_dialog_open_finish (dialog, result, NULL);
    if (file == NULL) return;

    g_free (self->compute_filename);
    self->compute_filename = g_file_get_path (file);
    g_autofree gchar *basename = g_file_get_basename (file);
    gtk_label_set_text (self->compute_file_label, basename);

    /* Clear cache and results */
    g_hash_table_remove_all (self->hash_cache);
    for (gint i = 0; i < NUM_HASH_ALGOS; i++) {
        gtk_label_set_text (GTK_LABEL (self->hash_result_labels[i]), "");
        if (gtk_switch_get_active (GTK_SWITCH (self->hash_switches[i]))) {
            gtk_switch_set_active (GTK_SWITCH (self->hash_switches[i]), FALSE);
        }
    }
}


static void
compute_choose_file_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoHashingPage *self = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, "Choose file to hash");
    GtkWidget *toplevel = GTK_WIDGET (gtk_widget_get_root (GTK_WIDGET (self)));
    gtk_file_dialog_open (dialog, GTK_WINDOW (toplevel), NULL,
                          compute_file_chosen_cb, self);
}


/* ---- Copy hash to clipboard ---- */

static void
copy_hash_clicked_cb (GtkButton *btn, gpointer user_data)
{
    GtkLabel *label = GTK_LABEL (user_data);
    const gchar *text = gtk_label_get_text (label);
    if (text && *text) {
        GdkClipboard *clipboard = gdk_display_get_clipboard (
            gdk_display_get_default ());
        gdk_clipboard_set_text (clipboard, text);
    }
    (void)btn;
}


/* ---- Compare sub-page ---- */

static void
compare_file1_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoHashingPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GFile) file = gtk_file_dialog_open_finish (dialog, result, NULL);
    if (file == NULL) return;

    g_free (self->compare_file1);
    self->compare_file1 = g_file_get_path (file);
    g_autofree gchar *basename = g_file_get_basename (file);
    gtk_label_set_text (self->file1_label, basename);
}

static void
compare_file2_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoHashingPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GFile) file = gtk_file_dialog_open_finish (dialog, result, NULL);
    if (file == NULL) return;

    g_free (self->compare_file2);
    self->compare_file2 = g_file_get_path (file);
    g_autofree gchar *basename = g_file_get_basename (file);
    gtk_label_set_text (self->file2_label, basename);
}

static void
compare_choose_file1_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoHashingPage *self = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, "Choose first file");
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
    gtk_file_dialog_set_title (dialog, "Choose second file");
    GtkWidget *toplevel = GTK_WIDGET (gtk_widget_get_root (GTK_WIDGET (self)));
    gtk_file_dialog_open (dialog, GTK_WINDOW (toplevel), NULL,
                          compare_file2_chosen_cb, self);
}


static gboolean
compare_result_idle (gpointer user_data)
{
    CompareThreadData *cd = user_data;

    gtk_spinner_stop (cd->page->compare_spinner);
    gtk_widget_set_sensitive (cd->page->compare_btn, TRUE);

    if (cd->hash1 == NULL || cd->hash2 == NULL) {
        gtk_label_set_text (cd->page->compare_result_label, "Error computing hash");
        gtk_widget_remove_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-match");
        gtk_widget_add_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-mismatch");
    } else if (g_strcmp0 (cd->hash1, cd->hash2) == 0) {
        gtk_label_set_text (cd->page->compare_result_label, "Hashes match");
        gtk_widget_remove_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-mismatch");
        gtk_widget_add_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-match");
    } else {
        gtk_label_set_text (cd->page->compare_result_label, "Hashes do NOT match");
        gtk_widget_remove_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-match");
        gtk_widget_add_css_class (GTK_WIDGET (cd->page->compare_result_label), "hash-mismatch");
    }

    g_free (cd->hash1);
    g_free (cd->hash2);
    g_free (cd);
    return G_SOURCE_REMOVE;
}


static gpointer
compare_thread_func (gpointer user_data)
{
    CompareThreadData *cd = user_data;
    GtkcryptoHashingPage *self = cd->page;

    guint selected = adw_combo_row_get_selected (self->compare_algo_row);
    gint algo = compare_algo_ids[selected];
    gint digest = compare_digest_sizes[selected];

    cd->hash1 = get_file_hash (self->compare_file1, algo, digest);
    cd->hash2 = get_file_hash (self->compare_file2, algo, digest);

    g_idle_add (compare_result_idle, cd);
    return NULL;
}


static void
compare_btn_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoHashingPage *self = user_data;

    if (self->compare_file1 == NULL || self->compare_file2 == NULL) {
        gtk_label_set_text (self->compare_result_label, "Please select both files first");
        return;
    }

    gtk_widget_set_sensitive (self->compare_btn, FALSE);
    gtk_spinner_start (self->compare_spinner);
    gtk_label_set_text (self->compare_result_label, "Computing...");

    CompareThreadData *cd = g_new0 (CompareThreadData, 1);
    cd->page = self;
    g_thread_new ("compare-hash", compare_thread_func, cd);
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
    GtkWidget *file_btn = gtk_button_new_with_label ("Choose File");
    gtk_widget_add_css_class (file_btn, "suggested-action");
    self->compute_file_label = GTK_LABEL (gtk_label_new ("No file selected"));
    gtk_label_set_ellipsize (self->compute_file_label, PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_set_hexpand (GTK_WIDGET (self->compute_file_label), TRUE);
    gtk_box_append (GTK_BOX (file_box), file_btn);
    gtk_box_append (GTK_BOX (file_box), GTK_WIDGET (self->compute_file_label));
    gtk_box_append (GTK_BOX (page), file_box);
    g_signal_connect (file_btn, "clicked", G_CALLBACK (compute_choose_file_cb), self);

    /* Hash algorithm list */
    GtkWidget *prefs_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (prefs_group), "Hash Algorithms");
    adw_preferences_group_set_description (ADW_PREFERENCES_GROUP (prefs_group),
                                           "Toggle algorithms to compute their hash");

    for (gint i = 0; i < NUM_HASH_ALGOS; i++) {
        GtkWidget *row = adw_action_row_new ();
        adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row), hash_algos[i].label);
        self->hash_rows[i] = row;

        /* Switch to enable/disable */
        GtkWidget *sw = gtk_switch_new ();
        gtk_widget_set_valign (sw, GTK_ALIGN_CENTER);
        self->hash_switches[i] = sw;
        adw_action_row_add_prefix (ADW_ACTION_ROW (row), sw);
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
        gtk_widget_set_valign (copy_btn, GTK_ALIGN_CENTER);
        gtk_widget_add_css_class (copy_btn, "flat");
        gtk_widget_set_tooltip_text (copy_btn, "Copy to clipboard");
        adw_action_row_add_suffix (ADW_ACTION_ROW (row), copy_btn);
        g_signal_connect (copy_btn, "clicked", G_CALLBACK (copy_hash_clicked_cb), result_label);

        adw_preferences_group_add (ADW_PREFERENCES_GROUP (prefs_group), row);
    }

    GtkWidget *scroll = gtk_scrolled_window_new ();
    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
                                    GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand (scroll, TRUE);

    GtkWidget *clamp = adw_clamp_new ();
    adw_clamp_set_child (ADW_CLAMP (clamp), prefs_group);
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
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (prefs1), "First File");
    GtkWidget *file1_row = adw_action_row_new ();
    self->file1_label = GTK_LABEL (gtk_label_new ("No file selected"));
    gtk_label_set_ellipsize (self->file1_label, PANGO_ELLIPSIZE_MIDDLE);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file1_row), GTK_WIDGET (self->file1_label));
    GtkWidget *file1_btn = gtk_button_new_from_icon_name ("document-open-symbolic");
    gtk_widget_set_valign (file1_btn, GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file1_row), file1_btn);
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (file1_row), "File");
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (prefs1), file1_row);
    g_signal_connect (file1_btn, "clicked", G_CALLBACK (compare_choose_file1_cb), self);

    /* File 2 */
    GtkWidget *prefs2 = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (prefs2), "Second File");
    GtkWidget *file2_row = adw_action_row_new ();
    self->file2_label = GTK_LABEL (gtk_label_new ("No file selected"));
    gtk_label_set_ellipsize (self->file2_label, PANGO_ELLIPSIZE_MIDDLE);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file2_row), GTK_WIDGET (self->file2_label));
    GtkWidget *file2_btn = gtk_button_new_from_icon_name ("document-open-symbolic");
    gtk_widget_set_valign (file2_btn, GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file2_row), file2_btn);
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (file2_row), "File");
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (prefs2), file2_row);
    g_signal_connect (file2_btn, "clicked", G_CALLBACK (compare_choose_file2_cb), self);

    /* Algorithm selection */
    GtkWidget *algo_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (algo_group), "Algorithm");
    self->compare_algo_row = ADW_COMBO_ROW (adw_combo_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->compare_algo_row), "Hash Algorithm");
    GtkStringList *algo_list = gtk_string_list_new (compare_algo_labels);
    adw_combo_row_set_model (self->compare_algo_row, G_LIST_MODEL (algo_list));
    adw_combo_row_set_selected (self->compare_algo_row, 3); /* SHA-512 default */
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (algo_group),
                               GTK_WIDGET (self->compare_algo_row));

    /* Compare button & result */
    GtkWidget *action_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign (action_box, GTK_ALIGN_CENTER);
    self->compare_btn = gtk_button_new_with_label ("Compare");
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

    /* View switcher in a toolbar */
    self->view_stack = ADW_VIEW_STACK (adw_view_stack_new ());

    GtkWidget *switcher_bar = adw_view_switcher_new ();
    adw_view_switcher_set_stack (ADW_VIEW_SWITCHER (switcher_bar), self->view_stack);
    adw_view_switcher_set_policy (ADW_VIEW_SWITCHER (switcher_bar), ADW_VIEW_SWITCHER_POLICY_WIDE);
    gtk_widget_set_halign (switcher_bar, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top (switcher_bar, 8);

    GtkWidget *compute_page = build_compute_page (self);
    AdwViewStackPage *cp = adw_view_stack_add_titled (self->view_stack, compute_page, "compute", "Compute");
    adw_view_stack_page_set_icon_name (cp, "accessories-calculator-symbolic");

    GtkWidget *compare_page = build_compare_page (self);
    AdwViewStackPage *cmp = adw_view_stack_add_titled (self->view_stack, compare_page, "compare", "Compare");
    adw_view_stack_page_set_icon_name (cmp, "view-dual-symbolic");

    gtk_box_append (GTK_BOX (self), switcher_bar);
    gtk_box_append (GTK_BOX (self), GTK_WIDGET (self->view_stack));
    gtk_widget_set_vexpand (GTK_WIDGET (self->view_stack), TRUE);
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
