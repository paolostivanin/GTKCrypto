#include "gpg-page.h"
#include "../gpgme-misc.h"
#include "../gtkcrypto.h"

struct _GtkcryptoGpgPage {
    GtkBox parent_instance;

    AdwViewStack *view_stack;

    /* Sign sub-page */
    GtkLabel         *sign_file_label;
    gchar            *sign_filename;
    AdwComboRow      *key_row;
    GSList           *gpg_keys;
    GtkWidget        *sign_btn;
    GtkSpinner       *sign_spinner;
    AdwToastOverlay  *sign_toast_overlay;

    /* Verify sub-page */
    GtkLabel         *verify_file_label;
    GtkLabel         *verify_sig_label;
    gchar            *verify_signed_file;
    gchar            *verify_sig_file;
    GtkWidget        *verify_btn;
    GtkSpinner       *verify_spinner;
    AdwToastOverlay  *verify_toast_overlay;
};

G_DEFINE_TYPE (GtkcryptoGpgPage, gtkcrypto_gpg_page, GTK_TYPE_BOX)


/* ---- Sign callbacks ---- */

typedef struct {
    GtkcryptoGpgPage *page;
    gchar *message;
    gboolean success;
} SignResultData;


static gboolean
sign_result_idle (gpointer user_data)
{
    SignResultData *d = user_data;
    gtk_spinner_stop (d->page->sign_spinner);
    gtk_widget_set_sensitive (d->page->sign_btn, TRUE);
    adw_toast_overlay_add_toast (d->page->sign_toast_overlay, adw_toast_new (d->message));
    g_free (d->message);
    g_free (d);
    return G_SOURCE_REMOVE;
}


static gpointer
sign_thread_func (gpointer user_data)
{
    SignResultData *d = user_data;
    GtkcryptoGpgPage *self = d->page;

    guint selected = adw_combo_row_get_selected (self->key_row);
    KeyInfo *key_info = g_slist_nth_data (self->gpg_keys, selected);

    gpointer status = sign_file (self->sign_filename, key_info->key_fpr);

    if (status == SIGN_OK) {
        d->message = g_strdup_printf ("File signed successfully (key: %s)", key_info->key_id);
        d->success = TRUE;
    } else {
        d->message = g_strdup ("Failed to sign file");
        d->success = FALSE;
    }

    g_idle_add (sign_result_idle, d);
    return NULL;
}


static void
sign_file_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoGpgPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GFile) file = gtk_file_dialog_open_finish (dialog, result, NULL);
    if (file == NULL) return;

    g_free (self->sign_filename);
    self->sign_filename = g_file_get_path (file);
    g_autofree gchar *basename = g_file_get_basename (file);
    gtk_label_set_text (self->sign_file_label, basename);
}


static void
sign_choose_file_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoGpgPage *self = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, "Choose file to sign");
    GtkWidget *toplevel = GTK_WIDGET (gtk_widget_get_root (GTK_WIDGET (self)));
    gtk_file_dialog_open (dialog, GTK_WINDOW (toplevel), NULL,
                          sign_file_chosen_cb, self);
}


static void
sign_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoGpgPage *self = user_data;

    if (self->sign_filename == NULL) {
        adw_toast_overlay_add_toast (self->sign_toast_overlay, adw_toast_new ("No file selected"));
        return;
    }

    if (self->gpg_keys == NULL) {
        adw_toast_overlay_add_toast (self->sign_toast_overlay, adw_toast_new ("No GPG keys available"));
        return;
    }

    gtk_widget_set_sensitive (self->sign_btn, FALSE);
    gtk_spinner_start (self->sign_spinner);

    SignResultData *d = g_new0 (SignResultData, 1);
    d->page = self;
    g_thread_new ("sign-file", sign_thread_func, d);
}


/* ---- Verify callbacks ---- */

typedef struct {
    GtkcryptoGpgPage *page;
    gchar *message;
} VerifyResultData;


static gboolean
verify_result_idle (gpointer user_data)
{
    VerifyResultData *d = user_data;
    gtk_spinner_stop (d->page->verify_spinner);
    gtk_widget_set_sensitive (d->page->verify_btn, TRUE);
    adw_toast_overlay_add_toast (d->page->verify_toast_overlay, adw_toast_new (d->message));
    g_free (d->message);
    g_free (d);
    return G_SOURCE_REMOVE;
}


static gpointer
verify_thread_func (gpointer user_data)
{
    VerifyResultData *d = user_data;
    GtkcryptoGpgPage *self = d->page;

    gpointer status = verify_signature (self->verify_signed_file, self->verify_sig_file);

    if (status == SIGNATURE_OK) {
        d->message = g_strdup ("Signature is valid");
    } else if (status == SIGNATURE_OK_KEY_NOT_TRUSTED) {
        d->message = g_strdup ("Signature is valid (key not trusted)");
    } else if (status == BAD_SIGNATURE) {
        d->message = g_strdup ("Bad signature");
    } else {
        d->message = g_strdup ("Error verifying signature");
    }

    g_idle_add (verify_result_idle, d);
    return NULL;
}


static void
verify_signed_file_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoGpgPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GFile) file = gtk_file_dialog_open_finish (dialog, result, NULL);
    if (file == NULL) return;

    g_free (self->verify_signed_file);
    self->verify_signed_file = g_file_get_path (file);
    g_autofree gchar *basename = g_file_get_basename (file);
    gtk_label_set_text (self->verify_file_label, basename);
}


static void
verify_sig_file_chosen_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkcryptoGpgPage *self = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
    g_autoptr(GFile) file = gtk_file_dialog_open_finish (dialog, result, NULL);
    if (file == NULL) return;

    g_free (self->verify_sig_file);
    self->verify_sig_file = g_file_get_path (file);
    g_autofree gchar *basename = g_file_get_basename (file);
    gtk_label_set_text (self->verify_sig_label, basename);
}


static void
verify_choose_file_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoGpgPage *self = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, "Choose signed file");
    GtkWidget *toplevel = GTK_WIDGET (gtk_widget_get_root (GTK_WIDGET (self)));
    gtk_file_dialog_open (dialog, GTK_WINDOW (toplevel), NULL,
                          verify_signed_file_chosen_cb, self);
}


static void
verify_choose_sig_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoGpgPage *self = user_data;
    GtkFileDialog *dialog = gtk_file_dialog_new ();
    gtk_file_dialog_set_title (dialog, "Choose signature (.sig) file");
    GtkWidget *toplevel = GTK_WIDGET (gtk_widget_get_root (GTK_WIDGET (self)));
    gtk_file_dialog_open (dialog, GTK_WINDOW (toplevel), NULL,
                          verify_sig_file_chosen_cb, self);
}


static void
verify_clicked_cb (GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkcryptoGpgPage *self = user_data;

    if (self->verify_signed_file == NULL || self->verify_sig_file == NULL) {
        adw_toast_overlay_add_toast (self->verify_toast_overlay,
                                     adw_toast_new ("Please select both files"));
        return;
    }

    gtk_widget_set_sensitive (self->verify_btn, FALSE);
    gtk_spinner_start (self->verify_spinner);

    VerifyResultData *d = g_new0 (VerifyResultData, 1);
    d->page = self;
    g_thread_new ("verify-sig", verify_thread_func, d);
}


/* ---- Key list factory ---- */

static void
key_list_factory_setup (GtkSignalListItemFactory *factory,
                        GtkListItem              *item,
                        gpointer                  user_data)
{
    (void)factory;
    (void)user_data;

    GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_margin_top (box, 6);
    gtk_widget_set_margin_bottom (box, 6);
    gtk_widget_set_margin_start (box, 6);
    gtk_widget_set_margin_end (box, 6);

    GtkWidget *name_label = gtk_label_new (NULL);
    gtk_label_set_xalign (GTK_LABEL (name_label), 0);
    gtk_label_set_ellipsize (GTK_LABEL (name_label), PANGO_ELLIPSIZE_END);
    gtk_widget_add_css_class (name_label, "heading");

    GtkWidget *detail_label = gtk_label_new (NULL);
    gtk_label_set_xalign (GTK_LABEL (detail_label), 0);
    gtk_label_set_ellipsize (GTK_LABEL (detail_label), PANGO_ELLIPSIZE_END);
    gtk_widget_add_css_class (detail_label, "dim-label");
    gtk_widget_add_css_class (detail_label, "caption");

    gtk_box_append (GTK_BOX (box), name_label);
    gtk_box_append (GTK_BOX (box), detail_label);

    gtk_list_item_set_child (item, box);
}


static void
key_list_factory_bind (GtkSignalListItemFactory *factory,
                       GtkListItem              *item,
                       gpointer                  user_data)
{
    (void)factory;
    (void)user_data;

    GtkStringObject *obj = GTK_STRING_OBJECT (gtk_list_item_get_item (item));
    const gchar *str = gtk_string_object_get_string (obj);

    GtkWidget *box = gtk_list_item_get_child (item);
    GtkWidget *name_label = gtk_widget_get_first_child (box);
    GtkWidget *detail_label = gtk_widget_get_next_sibling (name_label);

    /* Parse "Name <email> (key_id)" */
    const gchar *angle = g_strstr_len (str, -1, " <");
    if (angle != NULL) {
        g_autofree gchar *name = g_strndup (str, (gsize)(angle - str));
        gtk_label_set_text (GTK_LABEL (name_label), name);
        gtk_label_set_text (GTK_LABEL (detail_label), angle + 1);
    } else {
        gtk_label_set_text (GTK_LABEL (name_label), str);
        gtk_label_set_text (GTK_LABEL (detail_label), "");
    }
}


/* ---- Build UI ---- */

static GtkWidget *
build_sign_page (GtkcryptoGpgPage *self)
{
    self->sign_toast_overlay = ADW_TOAST_OVERLAY (adw_toast_overlay_new ());

    GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top (page, 24);
    gtk_widget_set_margin_bottom (page, 24);
    gtk_widget_set_margin_start (page, 24);
    gtk_widget_set_margin_end (page, 24);

    GtkWidget *clamp = adw_clamp_new ();
    adw_clamp_set_maximum_size (ADW_CLAMP (clamp), 700);
    gtk_widget_set_vexpand (clamp, TRUE);

    GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 16);

    /* File selection */
    GtkWidget *file_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (file_group), "File");
    GtkWidget *file_row = adw_action_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (file_row), "File to sign");
    self->sign_file_label = GTK_LABEL (gtk_label_new ("No file selected"));
    gtk_label_set_ellipsize (self->sign_file_label, PANGO_ELLIPSIZE_MIDDLE);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file_row), GTK_WIDGET (self->sign_file_label));
    GtkWidget *file_btn = gtk_button_new_from_icon_name ("document-open-symbolic");
    gtk_widget_set_valign (file_btn, GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file_row), file_btn);
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (file_group), file_row);
    g_signal_connect (file_btn, "clicked", G_CALLBACK (sign_choose_file_cb), self);

    /* Key selection */
    GtkWidget *key_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (key_group), "GPG Key");
    self->key_row = ADW_COMBO_ROW (adw_combo_row_new ());
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (self->key_row), "Signing Key");

    /* Populate keys */
    self->gpg_keys = get_available_keys ();
    GtkStringList *key_list = gtk_string_list_new (NULL);
    if (self->gpg_keys != NULL && self->gpg_keys != GPGME_ERROR) {
        for (GSList *l = self->gpg_keys; l; l = l->next) {
            KeyInfo *ki = l->data;
            gchar *display = g_strdup_printf ("%s <%s> (%s)", ki->name, ki->email, ki->key_id);
            gtk_string_list_append (key_list, display);
            g_free (display);
        }
    } else {
        self->gpg_keys = NULL;
        gtk_string_list_append (key_list, "No keys available");
    }
    adw_combo_row_set_model (self->key_row, G_LIST_MODEL (key_list));

    GtkListItemFactory *list_factory = gtk_signal_list_item_factory_new ();
    g_signal_connect (list_factory, "setup", G_CALLBACK (key_list_factory_setup), NULL);
    g_signal_connect (list_factory, "bind", G_CALLBACK (key_list_factory_bind), NULL);
    adw_combo_row_set_list_factory (self->key_row, list_factory);
    g_object_unref (list_factory);

    adw_preferences_group_add (ADW_PREFERENCES_GROUP (key_group), GTK_WIDGET (self->key_row));

    /* Sign button */
    GtkWidget *action_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign (action_box, GTK_ALIGN_CENTER);
    self->sign_btn = gtk_button_new ();
    GtkWidget *sign_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append (GTK_BOX (sign_box), gtk_image_new_from_icon_name ("document-edit-symbolic"));
    gtk_box_append (GTK_BOX (sign_box), gtk_label_new ("Sign"));
    gtk_button_set_child (GTK_BUTTON (self->sign_btn), sign_box);
    gtk_widget_add_css_class (self->sign_btn, "suggested-action");
    gtk_widget_add_css_class (self->sign_btn, "pill");
    self->sign_spinner = GTK_SPINNER (gtk_spinner_new ());
    gtk_box_append (GTK_BOX (action_box), self->sign_btn);
    gtk_box_append (GTK_BOX (action_box), GTK_WIDGET (self->sign_spinner));
    g_signal_connect (self->sign_btn, "clicked", G_CALLBACK (sign_clicked_cb), self);

    gtk_box_append (GTK_BOX (inner), file_group);
    gtk_box_append (GTK_BOX (inner), key_group);
    gtk_box_append (GTK_BOX (inner), action_box);

    adw_clamp_set_child (ADW_CLAMP (clamp), inner);
    gtk_box_append (GTK_BOX (page), clamp);

    adw_toast_overlay_set_child (self->sign_toast_overlay, page);
    return GTK_WIDGET (self->sign_toast_overlay);
}


static GtkWidget *
build_verify_page (GtkcryptoGpgPage *self)
{
    self->verify_toast_overlay = ADW_TOAST_OVERLAY (adw_toast_overlay_new ());

    GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top (page, 24);
    gtk_widget_set_margin_bottom (page, 24);
    gtk_widget_set_margin_start (page, 24);
    gtk_widget_set_margin_end (page, 24);

    GtkWidget *clamp = adw_clamp_new ();
    adw_clamp_set_maximum_size (ADW_CLAMP (clamp), 700);
    gtk_widget_set_vexpand (clamp, TRUE);

    GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 16);

    /* Signed file */
    GtkWidget *file_group = adw_preferences_group_new ();
    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (file_group), "Files");

    GtkWidget *file_row = adw_action_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (file_row), "Signed file");
    self->verify_file_label = GTK_LABEL (gtk_label_new ("No file selected"));
    gtk_label_set_ellipsize (self->verify_file_label, PANGO_ELLIPSIZE_MIDDLE);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file_row), GTK_WIDGET (self->verify_file_label));
    GtkWidget *file_btn = gtk_button_new_from_icon_name ("document-open-symbolic");
    gtk_widget_set_valign (file_btn, GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (file_row), file_btn);
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (file_group), file_row);
    g_signal_connect (file_btn, "clicked", G_CALLBACK (verify_choose_file_cb), self);

    GtkWidget *sig_row = adw_action_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (sig_row), "Signature (.sig) file");
    self->verify_sig_label = GTK_LABEL (gtk_label_new ("No file selected"));
    gtk_label_set_ellipsize (self->verify_sig_label, PANGO_ELLIPSIZE_MIDDLE);
    adw_action_row_add_suffix (ADW_ACTION_ROW (sig_row), GTK_WIDGET (self->verify_sig_label));
    GtkWidget *sig_btn = gtk_button_new_from_icon_name ("document-open-symbolic");
    gtk_widget_set_valign (sig_btn, GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (sig_row), sig_btn);
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (file_group), sig_row);
    g_signal_connect (sig_btn, "clicked", G_CALLBACK (verify_choose_sig_cb), self);

    /* Verify button */
    GtkWidget *action_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign (action_box, GTK_ALIGN_CENTER);
    self->verify_btn = gtk_button_new ();
    GtkWidget *verify_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append (GTK_BOX (verify_box), gtk_image_new_from_icon_name ("object-select-symbolic"));
    gtk_box_append (GTK_BOX (verify_box), gtk_label_new ("Verify"));
    gtk_button_set_child (GTK_BUTTON (self->verify_btn), verify_box);
    gtk_widget_add_css_class (self->verify_btn, "suggested-action");
    gtk_widget_add_css_class (self->verify_btn, "pill");
    self->verify_spinner = GTK_SPINNER (gtk_spinner_new ());
    gtk_box_append (GTK_BOX (action_box), self->verify_btn);
    gtk_box_append (GTK_BOX (action_box), GTK_WIDGET (self->verify_spinner));
    g_signal_connect (self->verify_btn, "clicked", G_CALLBACK (verify_clicked_cb), self);

    gtk_box_append (GTK_BOX (inner), file_group);
    gtk_box_append (GTK_BOX (inner), action_box);

    adw_clamp_set_child (ADW_CLAMP (clamp), inner);
    gtk_box_append (GTK_BOX (page), clamp);

    adw_toast_overlay_set_child (self->verify_toast_overlay, page);
    return GTK_WIDGET (self->verify_toast_overlay);
}


static void
gtkcrypto_gpg_page_finalize (GObject *object)
{
    GtkcryptoGpgPage *self = GTKCRYPTO_GPG_PAGE (object);
    g_free (self->sign_filename);
    g_free (self->verify_signed_file);
    g_free (self->verify_sig_file);
    g_slist_free_full (self->gpg_keys, g_free);
    G_OBJECT_CLASS (gtkcrypto_gpg_page_parent_class)->finalize (object);
}


static void
gtkcrypto_gpg_page_init (GtkcryptoGpgPage *self)
{
    gtk_orientable_set_orientation (GTK_ORIENTABLE (self), GTK_ORIENTATION_VERTICAL);

    self->view_stack = ADW_VIEW_STACK (adw_view_stack_new ());

    GtkWidget *switcher = adw_view_switcher_new ();
    adw_view_switcher_set_stack (ADW_VIEW_SWITCHER (switcher), self->view_stack);
    adw_view_switcher_set_policy (ADW_VIEW_SWITCHER (switcher), ADW_VIEW_SWITCHER_POLICY_WIDE);
    gtk_widget_set_halign (switcher, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top (switcher, 8);

    GtkWidget *sign_page = build_sign_page (self);
    AdwViewStackPage *sign_vs_page = adw_view_stack_add_titled (self->view_stack, sign_page, "sign", "Sign");
    adw_view_stack_page_set_icon_name (sign_vs_page, "document-edit-symbolic");

    GtkWidget *verify_page = build_verify_page (self);
    AdwViewStackPage *verify_vs_page = adw_view_stack_add_titled (self->view_stack, verify_page, "verify", "Verify");
    adw_view_stack_page_set_icon_name (verify_vs_page, "object-select-symbolic");

    gtk_box_append (GTK_BOX (self), switcher);
    gtk_box_append (GTK_BOX (self), GTK_WIDGET (self->view_stack));
    gtk_widget_set_vexpand (GTK_WIDGET (self->view_stack), TRUE);
}


static void
gtkcrypto_gpg_page_class_init (GtkcryptoGpgPageClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    object_class->finalize = gtkcrypto_gpg_page_finalize;
}


GtkcryptoGpgPage *
gtkcrypto_gpg_page_new (void)
{
    return g_object_new (GTKCRYPTO_TYPE_GPG_PAGE, NULL);
}
