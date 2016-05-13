#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gcrypt.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include "gtkcrypto.h"
#include "main.h"


static void choose_file_dialog(GtkWidget *, struct main_vars *);

static void pwd_dialog(GtkWidget *, struct main_vars *);

static void hide_menu(struct main_vars *);

static void toggle_changed_cb(GtkToggleButton *, GtkWidget *);

static void compute_hash_dialog(GtkWidget *, GtkWidget *, const gchar *);


const gchar *bt_names[] = {"BtMd5", "BtGost", "BtSha1", "BtSha256", "BtSha3_256", "BtSha384", "BtSha3_384", "BtSha512",
                           "BtSha3_512", "BtWhirl"};

gpointer (*hash_func[NUM_OF_HASH])(gpointer) = {compute_md5, compute_gost94, compute_sha1, compute_sha2, compute_sha3,
                                                compute_sha2, compute_sha3, compute_sha2, compute_sha3,
                                                compute_whirlpool};


static void quit(GSimpleAction __attribute__((__unused__)) *action, GVariant __attribute__((__unused__)) *parameter,
                 gpointer app) {
    g_application_quit(G_APPLICATION (app));
}


enum {
    COLUMN_ACNM,
    NUM_COLUMNS
};

static GtkTreeModel *create_model(struct main_vars *main_var) {
    GtkListStore *store;
    GtkTreeIter iter;
    GSList *list;

    /* create list store */
    store = gtk_list_store_new(NUM_COLUMNS, G_TYPE_STRING);

    /* add data to the list store */
    for (list = main_var->filenames; list; list = list->next) {
        if (list->data) {
            // maybe use the basename instead of the full path? Evalute this option
            gtk_list_store_append(store, &iter);
            gtk_list_store_set(store, &iter, COLUMN_ACNM, list->data, -1);
            g_free(list->data);
        }
    }
    g_slist_free(main_var->filenames);

    return GTK_TREE_MODEL (store);
}


static void add_columns(GtkTreeView *treeview) {
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("File Name", renderer, "text", COLUMN_ACNM, NULL);
    gtk_tree_view_column_set_sort_column_id(column, COLUMN_ACNM);
    gtk_tree_view_append_column(treeview, column);
}


static void about(  GSimpleAction __attribute__((__unused__)) *action, GVariant __attribute__((__unused__)) *parameter,
                    gpointer __attribute__((__unused__)) data) {

    const gchar *authors[] = {
            "Paolo Stivanin <info@paolostivanin.com>",
            NULL,
    };

    GdkPixbuf *logo = create_logo(TRUE);

    GtkWidget *a_dialog = gtk_about_dialog_new();
    gtk_about_dialog_set_program_name(GTK_ABOUT_DIALOG (a_dialog), "GTKCrypto");
    if (logo != NULL)
        gtk_about_dialog_set_logo(GTK_ABOUT_DIALOG (a_dialog), logo);

    gtk_about_dialog_set_version(GTK_ABOUT_DIALOG (a_dialog), VERSION);
    gtk_about_dialog_set_copyright(GTK_ABOUT_DIALOG (a_dialog), "Copyright (C) 2015");
    gtk_about_dialog_set_comments(GTK_ABOUT_DIALOG (a_dialog),
                                  _("Encrypt and decrypt files using different cipher algo and different cipher mode or"
                                            " compute their hash using different algo"));
    gtk_about_dialog_set_license(GTK_ABOUT_DIALOG(a_dialog),
                                 "This program is free software: you can redistribute it and/or modify it under the terms"
                                         " of the GNU General Public License as published by the Free Software Foundation, either version 3 of"
                                         " the License, or (at your option) any later version.\n"
                                         "This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even"
                                         " the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. "
                                         "See the GNU General Public License for more details.\n"
                                         "You should have received a copy of the GNU General Public License along with this program."
                                         "\nIf not, see http://www.gnu.org/licenses\n\nGTKCrypto is Copyright (C) 2015 by Paolo Stivanin.\n");
    gtk_about_dialog_set_wrap_license(GTK_ABOUT_DIALOG (a_dialog), TRUE);
    gtk_about_dialog_set_website(GTK_ABOUT_DIALOG (a_dialog), "https://paolostivanin.com");
    gtk_about_dialog_set_authors(GTK_ABOUT_DIALOG (a_dialog), authors);
    gtk_dialog_run(GTK_DIALOG (a_dialog));
    gtk_widget_destroy(a_dialog);
}


static void startup(GtkApplication *application, gpointer __attribute__((__unused__)) data) {
    static const GActionEntry actions[] = {
            {"about", about},
            {"quit",  quit}
    };

    const gchar *quit_accels[2] = {"<Ctrl>Q", NULL};

    GMenu *menu, *section;

    g_action_map_add_action_entries(G_ACTION_MAP (application), actions, G_N_ELEMENTS (actions), application);

    gtk_application_set_accels_for_action(GTK_APPLICATION (application), "app.quit", quit_accels);

    menu = g_menu_new();

    section = g_menu_new();
    g_menu_append(section, _("About"), "app.about");
    g_menu_append_section(G_MENU (menu), NULL, G_MENU_MODEL (section));
    g_object_unref(section);

    section = g_menu_new();
    g_menu_append(section, _("Quit"), "app.quit");
    g_menu_append_section(G_MENU (menu), NULL, G_MENU_MODEL (section));
    g_object_unref(section);

    gtk_application_set_app_menu(application, G_MENU_MODEL (menu));
    g_object_unref(menu);
}


static void activate(GtkApplication *app, struct main_vars *main_var) {
    GtkWidget *button[NUM_OF_BUTTONS];
    GtkWidget *frame[2];
    GtkWidget *box[2];
    GtkWidget *grid;

    gint i, j = 0;
    const gchar *button_label[] = {"File", "Text", "Compute Hash", "Quit"};
    const gchar *frame_label[] = {"Encrypt", "Decrypt"};
    const gchar *button_name[] = {"butEn", "butDe", "butEnTxt", "butDeTxt", "butHa", "butQ"}; //button 0,1,2,3,4,5

    main_var->main_window = do_mainwin(app);

    if (!gcry_check_version("1.7.0")) {
        error_dialog(_("The required version of Gcrypt is 1.7.0 or greater."), main_var->main_window);
        return;
    }

    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    for (i = 0; i < NUM_OF_BUTTONS; i++) {
        if (i == 5)
            j++;

        button[i] = gtk_button_new_with_label(button_label[j]);
        gtk_widget_set_name(GTK_WIDGET (button[i]), button_name[i]);

        if (i % 2 != 0)
            j++;
    }

    for (i = 0; i < NUM_OF_FRAMES; i++)
        frame[i] = gtk_frame_new(frame_label[i]);

    for (i = 0; i < NUM_OF_BOXES; i++)
        box[i] = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);

    gtk_box_pack_start(GTK_BOX (box[0]), button[0], TRUE, TRUE, 2);
    gtk_box_pack_start(GTK_BOX (box[0]), button[2], TRUE, TRUE, 2);
    gtk_container_add(GTK_CONTAINER (frame[0]), box[0]);

    gtk_box_pack_start(GTK_BOX (box[1]), button[1], TRUE, TRUE, 2);
    gtk_box_pack_start(GTK_BOX (box[1]), button[3], TRUE, TRUE, 2);
    gtk_container_add(GTK_CONTAINER (frame[1]), box[1]);

    GValue bottom_margin = G_VALUE_INIT;
    if (!G_IS_VALUE (&bottom_margin))
        g_value_init(&bottom_margin, G_TYPE_UINT);
    g_value_set_uint(&bottom_margin, 2);
    for (i = 0; i < NUM_OF_BUTTONS; i++)
        g_object_set_property(G_OBJECT (button[i]), "margin-bottom", &bottom_margin);

    g_signal_connect (button[0], "clicked", G_CALLBACK(choose_file_dialog), main_var);
    g_signal_connect (button[1], "clicked", G_CALLBACK(choose_file_dialog), main_var);
    g_signal_connect (button[2], "clicked", G_CALLBACK(text_dialog), main_var->main_window);
    g_signal_connect (button[3], "clicked", G_CALLBACK(text_dialog), main_var->main_window);
    g_signal_connect (button[4], "clicked", G_CALLBACK(choose_file_dialog), main_var);
    g_signal_connect (button[5], "clicked", G_CALLBACK(quit), app);

    grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER (main_var->main_window), grid);
    gtk_grid_set_row_homogeneous(GTK_GRID (grid), TRUE);
    gtk_grid_set_column_homogeneous(GTK_GRID (grid), TRUE);
    gtk_grid_set_row_spacing(GTK_GRID (grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID (grid), 5);

    gtk_grid_attach(GTK_GRID (grid), frame[0], 0, 0, 3, 2);
    gtk_grid_attach(GTK_GRID (grid), frame[1], 0, 2, 3, 2);
    gtk_grid_attach(GTK_GRID (grid), button[4], 0, 5, 3, 1);
    gtk_grid_attach(GTK_GRID  (grid), button[5], 0, 6, 3, 1);

    gtk_widget_show_all(main_var->main_window);
}


gint main(gint argc, gchar *argv[]) {
    struct main_vars main_var;

    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALE_DIR);
    textdomain(PACKAGE);

    GtkApplication *app;
    gint status;

    GdkPixbuf *logo = create_logo(FALSE);

    if (logo != NULL)
        gtk_window_set_default_icon(logo);

    app = gtk_application_new("org.gtk.gtkcrypto", G_APPLICATION_FLAGS_NONE);
    g_signal_connect (app, "startup", G_CALLBACK(startup), NULL);
    g_signal_connect (app, "activate", G_CALLBACK(activate), &main_var);
    status = g_application_run(G_APPLICATION (app), argc, argv);
    g_object_unref(app);
    return status;
}


GtkWidget *do_mainwin(GtkApplication *app) {
    static GtkWidget *window = NULL;
    GtkWidget *header_bar;
    GtkWidget *box;

    GdkPixbuf *logo = create_logo(0);

    window = gtk_application_window_new(app);
    gtk_window_set_application(GTK_WINDOW (window), GTK_APPLICATION (app));
    gtk_window_set_position(GTK_WINDOW (window), GTK_WIN_POS_CENTER);
    gtk_window_set_resizable(GTK_WINDOW (window), FALSE);

    if (logo != NULL)
        gtk_window_set_icon(GTK_WINDOW (window), logo);

    gtk_container_set_border_width(GTK_CONTAINER (window), 10);

    gtk_widget_set_size_request(GTK_WIDGET (window), 350, 400);

    gchar headertext[HEADERBAR_BUF];
    g_snprintf(headertext, HEADERBAR_BUF - 1, _("GTKCrypto %s"), VERSION);
    headertext[HEADERBAR_BUF - 1] = '\0';

    header_bar = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR (header_bar), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR (header_bar), headertext);
    gtk_header_bar_set_has_subtitle(GTK_HEADER_BAR (header_bar), FALSE);

    box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(box), "linked");

    gtk_window_set_titlebar(GTK_WINDOW (window), header_bar);

    return window;
}


static void choose_file_dialog(GtkWidget *button, struct main_vars *main_var) {
    const gchar *name = gtk_widget_get_name(GTK_WIDGET (button));
    GtkWidget *file_dialog;

    file_dialog = gtk_file_chooser_dialog_new(_("Choose File"), GTK_WINDOW (main_var->main_window),
                                              GTK_FILE_CHOOSER_ACTION_OPEN, _("OK"), GTK_RESPONSE_ACCEPT,
                                              _("Cancel"), GTK_RESPONSE_REJECT, NULL);
    if (g_strcmp0(name, "butHa") == 0) {
        gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER (file_dialog), FALSE);
    }
    else {
        gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER (file_dialog), TRUE);
    }

    gint result = gtk_dialog_run(GTK_DIALOG (file_dialog));
    switch (result) {
        case GTK_RESPONSE_ACCEPT:
            if (g_strcmp0(name, "butHa") == 0) {
                main_var->filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER (file_dialog));
                if (!g_utf8_validate(main_var->filename, -1, NULL)) {
                    error_dialog(_("The name of the file you have chose isn't a valid UTF-8 string."),
                                 main_var->main_window);
                    g_free(main_var->filename);
                    break;
                }
                compute_hash_dialog(file_dialog, main_var->main_window, main_var->filename);
                g_free(main_var->filename);
            }
            else {
                if (g_strcmp0(name, "butEn") == 0)
                    main_var->encrypt = TRUE;
                else
                    main_var->encrypt = FALSE;

                main_var->filenames = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER (file_dialog));
                pwd_dialog(file_dialog, main_var);
            }
            break;

        default:
            break;
    }
    gtk_widget_destroy(file_dialog);
}


static void create_dialog_single_file(struct main_vars *main_var) {
    GtkWidget *content_area;
    gint result;

    main_var->filename = g_strdup(main_var->filenames->data);
    g_print("%s\n", main_var->filename);
    g_free(main_var->filenames->data);

    main_var->bar_dialog = gtk_dialog_new_with_buttons("Progress Bar", GTK_WINDOW (main_var->main_window),
                                                       GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, _("Close"),
                                                       GTK_RESPONSE_REJECT, NULL);

    gtk_widget_set_size_request(main_var->bar_dialog, 250, 80);
    gtk_dialog_set_response_sensitive(GTK_DIALOG (main_var->bar_dialog), GTK_RESPONSE_REJECT, FALSE);

    content_area = gtk_dialog_get_content_area(GTK_DIALOG (main_var->bar_dialog));
    main_var->pBar = gtk_progress_bar_new();

    gtk_container_add(GTK_CONTAINER (content_area), main_var->pBar);
    gtk_widget_show_all(main_var->bar_dialog);

    GThread *n = g_thread_new(NULL, crypt_file, main_var);

    result = gtk_dialog_run(GTK_DIALOG (main_var->bar_dialog));
    switch (result) {
        case GTK_RESPONSE_REJECT:
            g_thread_join(n);
            break;
        default:
            break;
    }

    g_free(main_var->filename);
    g_slist_free(main_var->filenames);

    gtk_widget_destroy(main_var->bar_dialog);
}


static void create_dialog_multiple_files(struct main_vars *main_var) {
    /* TODO:
     * - check if all the filenames are valid UTF8
     * - create a treeview with filename(s) and their enc status IF g_slist_length(GSList is > 1). Otherwise copy the only filename in main_var->filename and free it after
     */
    GtkWidget *diag, *content_area, *btn;
    GtkTreeModel *model;
    GtkWidget *treeview;
    GtkWidget *sw;
    gint result;

    diag = gtk_dialog_new();
    btn = gtk_dialog_add_button(GTK_DIALOG (diag), _("_OK"), GTK_RESPONSE_OK);
    gtk_window_set_transient_for(GTK_WINDOW (diag), GTK_WINDOW (main_var->main_window));
    gtk_window_set_default_size(GTK_WINDOW (diag), 280, 250);

    content_area = gtk_dialog_get_content_area(GTK_DIALOG (diag));

    sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (sw), GTK_SHADOW_ETCHED_IN);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (sw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX (content_area), sw, TRUE, TRUE, 0);

    /* create tree model */
    model = create_model(main_var);

    /* create tree view */
    treeview = gtk_tree_view_new_with_model(model);
    gtk_tree_view_set_search_column(GTK_TREE_VIEW (treeview), COLUMN_ACNM);

    g_object_unref(model);

    gtk_container_add(GTK_CONTAINER (sw), treeview);

    /* add columns to the tree view */
    add_columns(GTK_TREE_VIEW (treeview));

    gtk_widget_show_all(diag);

    result = gtk_dialog_run(GTK_DIALOG (diag));
    switch (result) {
        case GTK_RESPONSE_OK:
            break;
        default:
            break;
    }

    gtk_widget_destroy(diag);
}


static void pwd_dialog(GtkWidget *file_dialog, struct main_vars *main_var) {
    gtk_widget_hide(file_dialog);

    GtkWidget *dialog, *content_area, *grid, *info_area, *label[2];
    GtkWidget *header_bar = NULL, *box, *image, *popover;
    GtkWidget *info_bar, *info_label;
    GIcon *icon;
    GValue left_margin = G_VALUE_INIT;
    GValue top_margin = G_VALUE_INIT;
    gint result, ret_val;

    label[1] = NULL;

    restart:
    if (main_var->encrypt) {
        header_bar = gtk_header_bar_new();
        gtk_header_bar_set_show_close_button(GTK_HEADER_BAR (header_bar), FALSE);
        gtk_header_bar_set_title(GTK_HEADER_BAR (header_bar), _("Encryption Password"));
        gtk_header_bar_set_has_subtitle(GTK_HEADER_BAR (header_bar), FALSE);

        box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        gtk_style_context_add_class(gtk_widget_get_style_context(box), "linked");
        icon = g_themed_icon_new("emblem-system-symbolic");
        image = gtk_image_new_from_gicon(icon, GTK_ICON_SIZE_BUTTON);
        g_object_unref(icon);

        main_var->menu = gtk_toggle_button_new();
        gtk_container_add(GTK_CONTAINER (main_var->menu), image);
        gtk_widget_set_tooltip_text(GTK_WIDGET (main_var->menu), _("Settings"));

        popover = create_popover(main_var->menu, GTK_POS_TOP, main_var);
        gtk_popover_set_modal(GTK_POPOVER (popover), TRUE);
        g_signal_connect (main_var->menu, "toggled", G_CALLBACK(toggle_changed_cb), popover);

        gtk_header_bar_pack_start(GTK_HEADER_BAR (header_bar), GTK_WIDGET(main_var->menu));
    }

    GtkDialogFlags flags = GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT;
    dialog = gtk_dialog_new_with_buttons("Password", GTK_WINDOW (main_var->main_window), flags,
                                         _("OK"), GTK_RESPONSE_ACCEPT, _("Cancel"), GTK_RESPONSE_REJECT, NULL);

    content_area = gtk_dialog_get_content_area(GTK_DIALOG (dialog));
    if (main_var->encrypt) {
        gtk_window_set_titlebar(GTK_WINDOW (dialog), header_bar);
        gtk_widget_add_events(GTK_WIDGET (dialog), GDK_BUTTON_PRESS_MASK);
        g_signal_connect_swapped (dialog, "button-press-event", G_CALLBACK(hide_menu), main_var);
    }

    label[0] = gtk_label_new(_("Type password"));
    if (main_var->encrypt) {
        label[1] = gtk_label_new(_("Retype password"));
        main_var->pwd_entry[1] = gtk_entry_new();
        gtk_entry_set_visibility(GTK_ENTRY (main_var->pwd_entry[1]), FALSE);
    }

    main_var->pwd_entry[0] = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY (main_var->pwd_entry[0]), FALSE);

    gtk_widget_set_size_request(dialog, 150, 100);

    info_bar = gtk_info_bar_new();

    if (main_var->encrypt)
        info_label = gtk_label_new(
                _("Encrypting and deleting the file can take some minutes depending on the file size..."));
    else
        info_label = gtk_label_new(_("Decrypting the file can take some minutes depending on the file size..."));

    gtk_label_set_justify(GTK_LABEL (info_label), GTK_JUSTIFY_CENTER);
    gtk_info_bar_set_message_type(GTK_INFO_BAR (info_bar), GTK_MESSAGE_INFO);
    info_area = gtk_info_bar_get_content_area(GTK_INFO_BAR (info_bar));
    gtk_container_add(GTK_CONTAINER (info_area), info_label);

    if (!G_IS_VALUE (&left_margin))
        g_value_init(&left_margin, G_TYPE_UINT);

    g_value_set_uint(&left_margin, 2);
    g_object_set_property(G_OBJECT (main_var->pwd_entry[0]), "margin-start", &left_margin);

    if (main_var->encrypt)
        g_object_set_property(G_OBJECT (main_var->pwd_entry[1]), "margin-start", &left_margin);

    if (!main_var->encrypt) {
        if (!G_IS_VALUE (&top_margin))
            g_value_init(&top_margin, G_TYPE_UINT);

        g_value_set_uint(&top_margin, 10);
        g_object_set_property(G_OBJECT (label[0]), "margin-top", &top_margin);
        g_object_set_property(G_OBJECT (main_var->pwd_entry[0]), "margin-top", &top_margin);
    }

    grid = gtk_grid_new();
    gtk_grid_set_column_homogeneous(GTK_GRID (grid), TRUE);
    gtk_grid_set_row_spacing(GTK_GRID (grid), 5);

    gtk_grid_attach(GTK_GRID (grid), label[0], 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID (grid), main_var->pwd_entry[0], 1, 0, 2, 1);
    if (main_var->encrypt) {
        gtk_grid_attach(GTK_GRID (grid), label[1], 0, 1, 1, 1);
        gtk_grid_attach(GTK_GRID (grid), main_var->pwd_entry[1], 1, 1, 2, 1);
        gtk_grid_attach(GTK_GRID (grid), info_bar, 0, 2, 3, 1);
    }
    else {
        gtk_grid_attach(GTK_GRID (grid), info_bar, 0, 1, 3, 1);
    }

    gtk_container_add(GTK_CONTAINER (content_area), grid);
    gtk_widget_show_all(dialog);

    result = gtk_dialog_run(GTK_DIALOG (dialog));
    switch (result) {
        case GTK_RESPONSE_ACCEPT:
            if (main_var->encrypt) {
                ret_val = check_pwd(main_var->pwd_entry[0], main_var->pwd_entry[1]);
                if (ret_val < 0) {
                    if (ret_val == PASSWORD_MISMATCH)
                        error_dialog(_("Passwords are different, try again.\n"), main_var->main_window);
                    else
                        error_dialog(_("Password is < 8 chars, try again\n"), main_var->main_window);

                    gtk_widget_destroy(dialog);
                    goto restart;
                }
                else {
                    gtk_widget_hide(dialog);
                    if (g_slist_length(main_var->filenames) == 1)
                        create_dialog_single_file(main_var);
                    else
                        create_dialog_multiple_files(main_var);
                }

            }
            else {
                main_var->hmac_error = FALSE;
                gtk_widget_hide(dialog);
                create_dialog_single_file(main_var);
                if (main_var->hmac_error) {
                    gtk_widget_destroy(dialog);
                    goto restart;
                }
            }
            break;

        case GTK_RESPONSE_REJECT:
            break;

        default:
            g_printerr(_("Exiting...\n"));
            break;
    }

    gtk_widget_destroy(dialog);
}


static void hide_menu(struct main_vars *main_var) {
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (main_var->menu)))
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (main_var->menu), FALSE);
}


static void toggle_changed_cb(GtkToggleButton *button, GtkWidget *popover) {
    gtk_widget_set_visible(popover, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button)));
}


static void compute_hash_dialog(GtkWidget *file_dialog, GtkWidget *main_window, const gchar *filename) {
    gtk_widget_hide(GTK_WIDGET (file_dialog));

    struct hash_vars hash_var;
    gint counter, i, result;

    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_path(css, "./src/style.css", NULL); // !!!! >> TODO: change path to /usr/share/gtkcrypto

    hash_var.mainwin = main_window;
    hash_var.hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    gsize filename_length = strlen(filename);

    hash_var.filename = g_malloc(filename_length + 1);
    if (hash_var.filename == NULL) {
        g_printerr(_("Error during memory allocation\n"));
        return;
    }
    g_utf8_strncpy(hash_var.filename, filename, filename_length);
    hash_var.filename[filename_length] = '\0';

    const gchar *label[] = {"MD5", "GOST94", "SHA-1", "SHA-256", "SHA3-256", "SHA-384", "SHA3-384", "SHA512",
                            "SHA3-512", "WHIRLPOOL"};
    gsize label_length;

    GtkWidget *content_area, *grid;

    hash_var.dialog = gtk_dialog_new();
    gtk_window_set_title(GTK_WINDOW (hash_var.dialog), _("Select Hash"));
    gtk_window_set_transient_for(GTK_WINDOW (hash_var.dialog), GTK_WINDOW (hash_var.mainwin));
    gtk_dialog_add_button(GTK_DIALOG (hash_var.dialog), _("Cancel"), GTK_RESPONSE_CANCEL);

    gtk_widget_set_size_request(hash_var.dialog, 800, 300);

    content_area = gtk_dialog_get_content_area(GTK_DIALOG (hash_var.dialog));

    for (i = 0; i < NUM_OF_HASH; i++) {
        label_length = g_utf8_strlen(label[i], -1);
        hash_var.key[i] = g_malloc(label_length + 1);
        g_utf8_strncpy(hash_var.key[i], label[i], label_length + 1);
    }

    for (i = 0; i < NUM_OF_HASH; i++) {
        hash_var.hash_check[i] = gtk_check_button_new_with_label(label[i]);
        hash_var.hash_entry[i] = gtk_entry_new();
        gtk_widget_set_name(GTK_WIDGET (hash_var.hash_entry[i]), "hash_entry");
        gtk_editable_set_editable(GTK_EDITABLE (hash_var.hash_entry[i]), FALSE);
        gtk_style_context_add_provider(gtk_widget_get_style_context(hash_var.hash_entry[i]), GTK_STYLE_PROVIDER (css),
                                       GTK_STYLE_PROVIDER_PRIORITY_USER);
    }

    grid = gtk_grid_new();
    gtk_grid_set_column_homogeneous(GTK_GRID (grid), FALSE);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 2);

    gint col = 0, row = 0, checkcolspan = 2, entrycolspan = 6, rowspan = 1;

    for (counter = 0; counter < NUM_OF_HASH; counter++) {
        //col, row, col span, row span
        gtk_grid_attach(GTK_GRID (grid), hash_var.hash_check[counter], col, row, checkcolspan, rowspan);
        gtk_grid_attach(GTK_GRID (grid), hash_var.hash_entry[counter], col + 2, row, entrycolspan, rowspan);
        gtk_widget_set_hexpand(GTK_WIDGET (hash_var.hash_entry[counter]), TRUE);
        row += 1;
    }

    gtk_container_add(GTK_CONTAINER (content_area), grid);
    gtk_widget_show_all(hash_var.dialog);

    for (i = 0; i < NUM_OF_HASH; i++) {
        gtk_widget_set_name(GTK_WIDGET (hash_var.hash_check[i]), bt_names[i]);
        hash_var.sig[i] = g_signal_connect (hash_var.hash_check[i], "clicked", G_CALLBACK(create_thread), &hash_var);
    }

    hash_var.pool = g_thread_pool_new((GFunc) launch_thread, (gpointer) &hash_var, g_get_num_processors(), FALSE, NULL);

    result = gtk_dialog_run(GTK_DIALOG (hash_var.dialog));
    switch (result) {
        case GTK_RESPONSE_CANCEL:
            g_thread_pool_free(hash_var.pool, FALSE, TRUE);
            g_free(hash_var.filename);
            g_hash_table_destroy(hash_var.hash_table);
            gtk_widget_destroy(hash_var.dialog);
            break;
    }
}


gpointer launch_thread(gpointer data, gpointer user_data) {
    gpointer (*func)(gpointer);
    func = data;
    func(user_data);
}


gboolean start_entry_progress(gpointer data) {
    gtk_entry_set_progress_pulse_step(GTK_ENTRY (data), 0.1);
    gtk_entry_progress_pulse(GTK_ENTRY (data));
    return TRUE;
}


gboolean stop_entry_progress(gpointer data) {
    struct IdleData *func = data;
    gtk_entry_set_progress_fraction(GTK_ENTRY (func->entry), 0.0);
    gtk_entry_set_text(GTK_ENTRY (func->entry), (gchar *) g_hash_table_lookup(func->hash_table, func->key));
    gtk_widget_set_sensitive(GTK_WIDGET (func->check), TRUE);
    g_slice_free (struct IdleData, func);
    return FALSE;
}


gboolean stop_btn(gpointer data) {
    struct hash_vars *func = data;
    gtk_dialog_set_response_sensitive(GTK_DIALOG (func->dialog), GTK_RESPONSE_CANCEL, FALSE);
    return FALSE;
}


gboolean start_btn(gpointer data) {
    struct hash_vars *func = data;
    if (g_thread_pool_get_num_threads(func->pool) == 1 && g_thread_pool_unprocessed(func->pool) == 0)
        gtk_dialog_set_response_sensitive(GTK_DIALOG (func->dialog), GTK_RESPONSE_CANCEL, TRUE);
    return FALSE;
}


gboolean delete_entry_text(gpointer data) {
    struct IdleData *func = data;
    gtk_entry_set_text(GTK_ENTRY (func->entry), "");
    gtk_widget_set_sensitive(GTK_WIDGET (func->check), TRUE);
    g_slice_free (struct IdleData, func);
    return FALSE;
}


gpointer create_thread(GtkWidget *bt, gpointer user_data) {
    gint i;
    struct hash_vars *hash_var = user_data;
    const gchar *name = gtk_widget_get_name(bt);
    const char *tmp_msg = _("For performance reason you shouldn't run\nmore threads than your system supports");
    char *msg;
    msg = g_malloc(strlen(tmp_msg) + 3 + 1); //msg len+max_core_len_(number btw 1 and 999)+\0
    g_snprintf(msg, strlen(tmp_msg) + 6, "%s (%d)", tmp_msg, g_get_num_processors());

    for (i = 0; i < NUM_OF_HASH; i++) {
        if (g_strcmp0(name, bt_names[i]) == 0) {
            if (g_strcmp0(name, "BtSha256") == 0 || g_strcmp0(name, "BtSha3_256") == 0)
                hash_var->n_bit = 256;
            else if (g_strcmp0(name, "BtSha384") == 0 || g_strcmp0(name, "BtSha3_384") == 0)
                hash_var->n_bit = 384;
            else if (g_strcmp0(name, "BtSha512") == 0 || g_strcmp0(name, "BtSha3_512") == 0)
                hash_var->n_bit = 512;

            if (g_thread_pool_get_num_threads(hash_var->pool) == g_get_num_processors()) {
                g_signal_handler_block(hash_var->hash_check[i], hash_var->sig[i]);
                if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (hash_var->hash_check[i])))
                    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (hash_var->hash_check[i]), FALSE);
                else
                    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (hash_var->hash_check[i]), TRUE);
                error_dialog(msg, hash_var->mainwin);
                g_free(msg);
                g_signal_handler_unblock(hash_var->hash_check[i], hash_var->sig[i]);
                return NULL;
            }

            gtk_widget_set_sensitive(GTK_WIDGET (hash_var->hash_check[i]), FALSE);
            g_thread_pool_push(hash_var->pool, hash_func[i], NULL);
        }
    }
    g_free(msg);
}
