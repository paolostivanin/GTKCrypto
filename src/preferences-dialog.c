#include <glib/gi18n.h>

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

    adw_preferences_dialog_add (dialog, page);
    adw_dialog_present (ADW_DIALOG (dialog), parent);
}
