#include <gtk/gtk.h>
#include "main.h"

void
startup (GtkApplication *application,
         gpointer __attribute__((__unused__)) data)
{
    static const GActionEntry actions[] = {
            {"about", about},
            {"quit",  quit}
    };

    const gchar *quit_accels[2] = {"<Ctrl>Q", NULL};

    g_action_map_add_action_entries (G_ACTION_MAP (application), actions, G_N_ELEMENTS (actions), application);

    gtk_application_set_accels_for_action (GTK_APPLICATION (application), "app.quit", quit_accels);

    GMenu *menu = g_menu_new ();

    GMenu *section = g_menu_new ();
    g_menu_append (section, "About", "app.about");
    g_menu_append_section (G_MENU (menu), NULL, G_MENU_MODEL (section));
    g_object_unref (section);

    section = g_menu_new ();
    g_menu_append (section, "Quit", "app.quit");
    g_menu_append_section (G_MENU (menu), NULL, G_MENU_MODEL (section));
    g_object_unref (section);

    gtk_application_set_app_menu (application, G_MENU_MODEL (menu));
    g_object_unref (menu);
}