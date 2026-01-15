#include <gtk/gtk.h>


static gchar *get_ui_path (const gchar *partial_path);
static gchar *find_ui_in_dir (const gchar *dir_path);


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
    gchar *system_path = g_build_filename ("/usr", partial_path, NULL);
    gchar *local_path = g_build_filename ("/usr/local", partial_path, NULL);
    if (g_file_test (system_path, G_FILE_TEST_EXISTS)) {
        path_to_ui_file = g_strdup (system_path);
    } else if (g_file_test (local_path, G_FILE_TEST_EXISTS)) {
        path_to_ui_file = g_strdup (local_path);
    } else {
        gchar *current_dir = g_get_current_dir ();
        gchar *search_dir = g_strdup (current_dir);
        for (gint depth = 0; depth < 4 && path_to_ui_file == NULL; depth++) {
            path_to_ui_file = find_ui_in_dir (search_dir);
            if (path_to_ui_file != NULL) {
                break;
            }

            gchar *parent_dir = g_path_get_dirname (search_dir);
            if (g_strcmp0 (parent_dir, search_dir) == 0) {
                g_free (parent_dir);
                break;
            }

            g_free (search_dir);
            search_dir = parent_dir;
        }

        g_free (search_dir);
        g_free (current_dir);
    }

    g_free (system_path);
    g_free (local_path);

    return path_to_ui_file;
}

static gchar *
find_ui_in_dir (const gchar *dir_path)
{
    const gchar *candidates[] = {
        "gtkcrypto.ui",
        "src/ui/gtkcrypto.ui",
        NULL
    };

    for (gint i = 0; candidates[i] != NULL; i++) {
        gchar *candidate_path = g_build_filename (dir_path, candidates[i], NULL);
        if (g_file_test (candidate_path, G_FILE_TEST_EXISTS)) {
            return candidate_path;
        }
        g_free (candidate_path);
    }

    return NULL;
}
