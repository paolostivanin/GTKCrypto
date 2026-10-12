#include <glib/gi18n.h>
#include "gtkcrypto-window.h"
#include "pages/hashing-page.h"
#include "pages/file-crypto-page.h"
#include "pages/text-crypto-page.h"
#include "pages/gpg-page.h"

struct _GtkcryptoWindow {
    AdwApplicationWindow parent_instance;

    AdwNavigationSplitView *split_view;
    GtkListBox             *sidebar;
    GtkStack               *content_stack;

    GtkcryptoHashingPage    *hashing_page;
    GtkcryptoFileCryptoPage *file_crypto_page;
    GtkcryptoTextCryptoPage *text_crypto_page;
    GtkcryptoGpgPage        *gpg_page;
};

G_DEFINE_TYPE (GtkcryptoWindow, gtkcrypto_window, ADW_TYPE_APPLICATION_WINDOW)

static gboolean close_request_cb (GtkWindow *window, gpointer user_data);
static void show_page_action_cb (GSimpleAction *action, GVariant *parameter,
                                 gpointer user_data);
static void show_shortcuts_action_cb (GSimpleAction *action, GVariant *parameter,
                                      gpointer user_data);

typedef struct {
    const gchar *title;
    const gchar *icon_name;
    const gchar *page_name;
} SidebarItem;

static const SidebarItem sidebar_items[] = {
    { N_("File Encryption"), "channel-secure-symbolic",   "file-crypto" },
    { N_("Text Encryption"), "document-edit-symbolic",    "text-crypto" },
    { N_("Hashing"),         "auth-fingerprint-symbolic",       "hashing"     },
    { N_("GPG Signing"),     "application-certificate-symbolic", "gpg"         },
};


static GtkWidget *
create_sidebar_row (const SidebarItem *item)
{
    GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_margin_top (box, 8);
    gtk_widget_set_margin_bottom (box, 8);
    gtk_widget_set_margin_start (box, 8);
    gtk_widget_set_margin_end (box, 8);

    GtkWidget *icon = gtk_image_new_from_icon_name (item->icon_name);
    gtk_box_append (GTK_BOX (box), icon);

    GtkWidget *label = gtk_label_new (_(item->title));
    gtk_box_append (GTK_BOX (box), label);

    GtkWidget *row = gtk_list_box_row_new ();
    gtk_list_box_row_set_child (GTK_LIST_BOX_ROW (row), box);
    g_object_set_data (G_OBJECT (row), "page-name", (gpointer)item->page_name);

    return row;
}


static void
sidebar_row_selected_cb (GtkListBox    *listbox,
                         GtkListBoxRow *row,
                         gpointer       user_data)
{
    (void)listbox;
    GtkcryptoWindow *self = GTKCRYPTO_WINDOW (user_data);

    if (row == NULL)
        return;

    const gchar *page_name = g_object_get_data (G_OBJECT (row), "page-name");
    gtk_stack_set_visible_child_name (self->content_stack, page_name);
    adw_navigation_split_view_set_show_content (self->split_view, TRUE);
}


static void
gtkcrypto_window_init (GtkcryptoWindow *self)
{
    /* Main layout */
    self->split_view = ADW_NAVIGATION_SPLIT_VIEW (adw_navigation_split_view_new ());
    adw_navigation_split_view_set_min_sidebar_width (self->split_view, 200);
    adw_navigation_split_view_set_max_sidebar_width (self->split_view, 260);
    adw_application_window_set_content (ADW_APPLICATION_WINDOW (self),
                                        GTK_WIDGET (self->split_view));

    /* Sidebar */
    GtkWidget *sidebar_toolbar = adw_toolbar_view_new ();
    AdwHeaderBar *sidebar_header = ADW_HEADER_BAR (adw_header_bar_new ());

    /* Primary menu with About */
    GMenu *menu = g_menu_new ();
    g_menu_append (menu, _("Preferences"), "app.preferences");
    g_menu_append (menu, _("Keyboard Shortcuts"), "win.show-shortcuts");
    g_menu_append (menu, _("About GTKCrypto"), "app.about");

    GtkWidget *menu_button = gtk_menu_button_new ();
    gtk_menu_button_set_icon_name (GTK_MENU_BUTTON (menu_button), "open-menu-symbolic");
    gtk_menu_button_set_menu_model (GTK_MENU_BUTTON (menu_button), G_MENU_MODEL (menu));
    gtk_widget_set_tooltip_text (menu_button, _("Main Menu"));
    adw_header_bar_pack_end (sidebar_header, menu_button);
    g_object_unref (menu);

    adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (sidebar_toolbar),
                                  GTK_WIDGET (sidebar_header));

    self->sidebar = GTK_LIST_BOX (gtk_list_box_new ());
    gtk_list_box_set_selection_mode (self->sidebar, GTK_SELECTION_SINGLE);
    gtk_widget_add_css_class (GTK_WIDGET (self->sidebar), "navigation-sidebar");

    for (gsize i = 0; i < G_N_ELEMENTS (sidebar_items); i++) {
        GtkWidget *row = create_sidebar_row (&sidebar_items[i]);
        gtk_list_box_append (self->sidebar, row);
    }

    GtkWidget *sidebar_scroll = gtk_scrolled_window_new ();
    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (sidebar_scroll),
                                    GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (sidebar_scroll),
                                   GTK_WIDGET (self->sidebar));
    adw_toolbar_view_set_content (ADW_TOOLBAR_VIEW (sidebar_toolbar), sidebar_scroll);

    AdwNavigationPage *sidebar_page = adw_navigation_page_new (sidebar_toolbar, "GTKCrypto");
    adw_navigation_split_view_set_sidebar (self->split_view, sidebar_page);

    /* Content area */
    GtkWidget *content_toolbar = adw_toolbar_view_new ();
    AdwHeaderBar *content_header = ADW_HEADER_BAR (adw_header_bar_new ());
    adw_header_bar_set_show_title (content_header, FALSE);
    adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (content_toolbar),
                                  GTK_WIDGET (content_header));

    self->content_stack = GTK_STACK (gtk_stack_new ());
    gtk_stack_set_transition_type (self->content_stack, GTK_STACK_TRANSITION_TYPE_CROSSFADE);

    /* Create pages */
    self->file_crypto_page = gtkcrypto_file_crypto_page_new ();
    self->text_crypto_page = gtkcrypto_text_crypto_page_new ();
    self->hashing_page = gtkcrypto_hashing_page_new ();
    self->gpg_page = gtkcrypto_gpg_page_new ();

    gtk_stack_add_named (self->content_stack,
                         GTK_WIDGET (self->file_crypto_page), "file-crypto");
    gtk_stack_add_named (self->content_stack,
                         GTK_WIDGET (self->text_crypto_page), "text-crypto");
    gtk_stack_add_named (self->content_stack,
                         GTK_WIDGET (self->hashing_page), "hashing");
    gtk_stack_add_named (self->content_stack,
                         GTK_WIDGET (self->gpg_page), "gpg");

    adw_toolbar_view_set_content (ADW_TOOLBAR_VIEW (content_toolbar),
                                  GTK_WIDGET (self->content_stack));

    AdwNavigationPage *content_page = adw_navigation_page_new (content_toolbar, "GTKCrypto");
    adw_navigation_split_view_set_content (self->split_view, content_page);

    /* Connect sidebar selection */
    g_signal_connect (self->sidebar, "row-selected",
                      G_CALLBACK (sidebar_row_selected_cb), self);

    /* Select first row by default */
    GtkListBoxRow *first_row = gtk_list_box_get_row_at_index (self->sidebar, 0);
    gtk_list_box_select_row (self->sidebar, first_row);

    g_signal_connect (self, "close-request", G_CALLBACK (close_request_cb), NULL);

    static const GActionEntry win_actions[] = {
        { "show-page", show_page_action_cb, "i", NULL, NULL, { 0 } },
        { "show-shortcuts", show_shortcuts_action_cb, NULL, NULL, NULL, { 0 } },
    };
    g_action_map_add_action_entries (G_ACTION_MAP (self), win_actions,
                                     G_N_ELEMENTS (win_actions), self);

    /* The sidebar is the only navigation: give it an accessible name. */
    gtk_accessible_update_property (GTK_ACCESSIBLE (self->sidebar),
                                    GTK_ACCESSIBLE_PROPERTY_LABEL,
                                    _("Sections"), -1);

    /* Window defaults */
    gtk_window_set_default_size (GTK_WINDOW (self), 900, 600);
    gtk_window_set_title (GTK_WINDOW (self), "GTKCrypto");
}


static void
show_page_action_cb (GSimpleAction *action, GVariant *parameter,
                     gpointer user_data)
{
    (void)action;
    GtkcryptoWindow *self = GTKCRYPTO_WINDOW (user_data);
    GtkListBoxRow *row = gtk_list_box_get_row_at_index (
        self->sidebar, g_variant_get_int32 (parameter));
    if (row != NULL) {
        gtk_list_box_select_row (self->sidebar, row);
    }
}


static void
add_shortcut_row (AdwPreferencesGroup *group, const gchar *title,
                  const gchar *accel)
{
    GtkWidget *row = adw_action_row_new ();
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row), title);
    GtkWidget *label = gtk_shortcut_label_new (accel);
    gtk_widget_set_valign (label, GTK_ALIGN_CENTER);
    adw_action_row_add_suffix (ADW_ACTION_ROW (row), label);
    adw_preferences_group_add (group, row);
}


static void
show_shortcuts_action_cb (GSimpleAction *action, GVariant *parameter,
                          gpointer user_data)
{
    (void)action; (void)parameter;
    AdwDialog *dialog = adw_dialog_new ();
    adw_dialog_set_title (dialog, _("Keyboard Shortcuts"));
    adw_dialog_set_content_width (dialog, 420);

    AdwPreferencesPage *page = ADW_PREFERENCES_PAGE (adw_preferences_page_new ());
    AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP (adw_preferences_group_new ());
    add_shortcut_row (group, _("File Encryption"), "<Control>1");
    add_shortcut_row (group, _("Text Encryption"), "<Control>2");
    add_shortcut_row (group, _("Hashing"), "<Control>3");
    add_shortcut_row (group, _("GPG Signing"), "<Control>4");
    add_shortcut_row (group, _("Preferences"), "<Control>comma");
    add_shortcut_row (group, _("Keyboard Shortcuts"), "<Control>question");
    add_shortcut_row (group, _("Quit"), "<Control>q");
    adw_preferences_page_add (page, group);

    GtkWidget *toolbar = adw_toolbar_view_new ();
    adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (toolbar), adw_header_bar_new ());
    adw_toolbar_view_set_content (ADW_TOOLBAR_VIEW (toolbar), GTK_WIDGET (page));
    adw_dialog_set_child (dialog, toolbar);
    adw_dialog_present (dialog, GTK_WIDGET (user_data));
}


static gboolean
close_request_cb (GtkWindow *window, gpointer user_data)
{
    (void)user_data;
    GtkcryptoWindow *self = GTKCRYPTO_WINDOW (window);
    gtkcrypto_file_crypto_page_shutdown (self->file_crypto_page);
    return FALSE;
}


static void
gtkcrypto_window_class_init (GtkcryptoWindowClass *klass)
{
    (void)klass;
    (void)gtkcrypto_window_parent_class;   /* silence -Wunused-but-set-global */
}


GtkcryptoWindow *
gtkcrypto_window_new (GtkcryptoApplication *app)
{
    return g_object_new (GTKCRYPTO_TYPE_WINDOW,
                         "application", app,
                         NULL);
}
