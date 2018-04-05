#include <gtk/gtk.h>


static gchar *get_ui_path (const gchar *partial_path);


GtkBuilder *
get_builder_from_path (const gchar *partial_path)
{
    gchar *ui_file_path = get_ui_path (partial_path);
    if (ui_file_path == NULL) {
        g_printerr ("Couldn't locate the ui file.\n");
        return NULL;
    }

    return gtk_builder_new_from_file (ui_file_path);
}


static gchar *
get_ui_path (const gchar *partial_path)
{
    gchar *path_to_ui_file = NULL;
    if (g_file_test (g_strconcat ("/usr/", partial_path, NULL), G_FILE_TEST_EXISTS)) {
        path_to_ui_file = g_strconcat ("/usr/", partial_path, NULL);
    } else if (g_file_test (g_strconcat ("/usr/local/", partial_path, NULL), G_FILE_TEST_EXISTS)) {
        path_to_ui_file = g_strconcat ("/usr/local/", partial_path, NULL);
    }

    return path_to_ui_file;
}