#include <glib/gi18n.h>

#include "crypt-common.h"
#include "preferences-dialog.h"
#include "state.h"

static void
clipboard_seconds_changed_cb (AdwSpinRow *row, GParamSpec *pspec,
                              gpointer user_data)
{
    (void)pspec; (void)user_data;
    gdouble value = adw_spin_row_get_value (row);
    state_set_int ("clipboard-clear-seconds", (gint)value);
}

static void
kdf_level_changed_cb (AdwComboRow *row, GParamSpec *pspec, gpointer user_data)
{
    (void)pspec; (void)user_data;
    guint selected = adw_combo_row_get_selected (row);
    state_set_int ("kdf-level", (gint)selected);
    gtkcrypto_set_kdf_level ((GtkcryptoKdfLevel)selected);
}

void
gtkcrypto_preferences_dialog_present (GtkWidget *parent)
{
    AdwPreferencesDialog *dialog = ADW_PREFERENCES_DIALOG (
        adw_preferences_dialog_new ());
    adw_dialog_set_title (ADW_DIALOG (dialog), _("Preferences"));

    AdwPreferencesPage *page = ADW_PREFERENCES_PAGE (adw_preferences_page_new ());

    AdwPreferencesGroup *privacy = ADW_PREFERENCES_GROUP (
        adw_preferences_group_new ());
    adw_preferences_group_set_title (privacy, _("Privacy"));

    GtkAdjustment *adj = gtk_adjustment_new (
        state_get_int ("clipboard-clear-seconds", 30), 0, 600, 5, 30, 0);
    GtkWidget *clip_row = adw_spin_row_new (adj, 5, 0);
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (clip_row),
                                   _("Clear clipboard after (seconds)"));
    adw_action_row_set_subtitle (ADW_ACTION_ROW (clip_row),
                                 _("Applies to decrypted text copied from the "
                                   "Text Encryption page. 0 keeps it forever."));
    g_signal_connect (clip_row, "notify::value",
                      G_CALLBACK (clipboard_seconds_changed_cb), NULL);
    adw_preferences_group_add (privacy, clip_row);
    adw_preferences_page_add (page, privacy);

    AdwPreferencesGroup *encryption = ADW_PREFERENCES_GROUP (
        adw_preferences_group_new ());
    adw_preferences_group_set_title (encryption, _("Encryption"));
    adw_preferences_group_set_description (
        encryption,
        _("Cost of deriving the key from your password when creating new "
          "encrypted files and texts. Existing data can always be opened."));
    const gchar *levels[] = {
        _("Standard (2 passes, 19 MiB)"),
        _("Strong (3 passes, 64 MiB)"),
        _("Maximum (4 passes, 256 MiB)"),
        NULL,
    };
    GtkWidget *kdf_row = adw_combo_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (kdf_row),
                                   _("Key derivation strength"));
    adw_action_row_set_subtitle (ADW_ACTION_ROW (kdf_row),
                                 _("Higher levels are slower and need more memory"));
    adw_combo_row_set_model (ADW_COMBO_ROW (kdf_row),
                             G_LIST_MODEL (gtk_string_list_new (levels)));
    GtkcryptoKdfLevel current = gtkcrypto_get_kdf_level ();
    adw_combo_row_set_selected (ADW_COMBO_ROW (kdf_row), (guint)current);
    g_signal_connect (kdf_row, "notify::selected",
                      G_CALLBACK (kdf_level_changed_cb), NULL);
    adw_preferences_group_add (encryption, kdf_row);
    adw_preferences_page_add (page, encryption);

    adw_preferences_dialog_add (dialog, page);
    adw_dialog_present (ADW_DIALOG (dialog), parent);
}
