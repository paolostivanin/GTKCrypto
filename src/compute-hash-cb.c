#include <gtk/gtk.h>
#include <gcrypt.h>
#include "gtkcrypto.h"
#include "common-callbacks.h"
#include "hash.h"


typedef struct compute_hash_widgets_t {
    GtkWidget *main_window;
    GtkWidget *cancel_btn;
    GtkWidget *check_button[AVAILABLE_HASH_TYPE];
    GtkWidget *hash_entry[AVAILABLE_HASH_TYPE];
    GtkWidget *spinner[AVAILABLE_HASH_TYPE];
    gchar *filename;
    GThreadPool *thread_pool;
} HashWidgets;

typedef struct compute_hash_thread_data_t {
    GtkWidget *ck_btn;
    gint hash_algo;
    gint digest_size;
    HashWidgets *widgets;
} ThreadData;

static void prepare_hash_computation_cb (GtkWidget *, gpointer);

static gpointer exec_thread (gpointer, gpointer);

static gboolean is_last_thread (GThreadPool *);


void
compute_hash_cb (GtkWidget *button __attribute((__unused__)),
                 gpointer user_data)
{
    const gchar *ck_btn_labels[] = {"MD5", "SHA-1", "GOST94", "SHA-256", "SHA3-256", "SHA-384", "SHA3-384",
                                    "SHA-512", "SHA3-512", "WHIRLPOOL"};

    HashWidgets *hash_widgets = g_new0 (HashWidgets, 1);
    hash_widgets->main_window = (GtkWidget *) user_data;

    hash_widgets->filename = choose_file (hash_widgets->main_window);

    GtkWidget *dialog = gtk_dialog_new ();
    gtk_widget_set_name (dialog, "dialog");
    gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (hash_widgets->main_window));
    gtk_window_set_destroy_with_parent (GTK_WINDOW (dialog), TRUE);
    gtk_window_set_title (GTK_WINDOW (dialog), "Compute File Hashes");

    hash_widgets->cancel_btn = gtk_dialog_add_button (GTK_DIALOG (dialog), "Cancel", GTK_RESPONSE_CANCEL);
    gtk_widget_set_margin_top (hash_widgets->cancel_btn, 10);
    gtk_widget_set_size_request (dialog, 800, -1);

    gint i;
    for (i = 0; i < AVAILABLE_HASH_TYPE; i++) {
        hash_widgets->check_button[i] = gtk_check_button_new_with_label (ck_btn_labels[i]);
        gtk_widget_set_name (hash_widgets->check_button[i], ck_btn_labels[i]);

        hash_widgets->spinner[i] = create_spinner ();
        gtk_widget_set_name (hash_widgets->spinner[i], ck_btn_labels[i]);

        hash_widgets->hash_entry[i] = gtk_entry_new ();
        gtk_widget_set_name (hash_widgets->hash_entry[i], ck_btn_labels[i]);
        gtk_editable_set_editable (GTK_EDITABLE (hash_widgets->hash_entry[i]), FALSE);
        gtk_widget_set_hexpand (hash_widgets->hash_entry[i], TRUE);

        gtk_entry_set_icon_from_icon_name (GTK_ENTRY (hash_widgets->hash_entry[i]), GTK_ENTRY_ICON_SECONDARY, "edit-copy-symbolic");
        gtk_entry_set_icon_tooltip_text (GTK_ENTRY (hash_widgets->hash_entry[i]), GTK_ENTRY_ICON_SECONDARY, "Copy to clipboard");

        g_signal_connect (hash_widgets->hash_entry[i], "icon-press", G_CALLBACK (copy_to_clipboard_cb), NULL);
        g_signal_connect (hash_widgets->check_button[i], "toggled", G_CALLBACK (prepare_hash_computation_cb), hash_widgets);
    }

    GtkWidget *content_area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
    GtkWidget *grid = gtk_grid_new ();
    gtk_container_add (GTK_CONTAINER (content_area), grid);
    gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
    gtk_grid_set_column_spacing (GTK_GRID (grid), 5);

    gint j;
    for (i = 0, j = 0; i < AVAILABLE_HASH_TYPE; i++, j++) {
        gtk_grid_attach (GTK_GRID (grid), hash_widgets->check_button[i], 0, j, 1, 1);
        gtk_grid_attach_next_to (GTK_GRID (grid), hash_widgets->hash_entry[i], hash_widgets->check_button[i], GTK_POS_RIGHT, 4, 1);
        gtk_grid_attach_next_to (GTK_GRID (grid), hash_widgets->spinner[i], hash_widgets->hash_entry[i], GTK_POS_RIGHT, 1, 1);
    }

    hash_widgets->thread_pool = g_thread_pool_new ((GFunc) exec_thread, NULL, g_get_num_processors (), FALSE, NULL);

    gtk_widget_show_all (dialog);

    gint result = gtk_dialog_run (GTK_DIALOG (dialog));
    switch (result) {
        case GTK_RESPONSE_CANCEL:
            gtk_widget_destroy (dialog);
            g_thread_pool_free (hash_widgets->thread_pool, FALSE, FALSE);
            multiple_free (2, (gpointer *) &(hash_widgets->filename), (gpointer *) &hash_widgets);
            break;
        default:
            break;
    }
}


static void
prepare_hash_computation_cb (GtkWidget *ck_btn, gpointer user_data)
{
    HashWidgets *data  = user_data;
    ThreadData *thread_data = g_new0 (ThreadData, 1);

    gint hash_algo = -1, digest_size = -1;

    if (g_strcmp0 (gtk_widget_get_name (ck_btn), "MD5") == 0) {
        hash_algo = GCRY_MD_MD5;
        digest_size = MD5_DIGEST_SIZE;
    }
    else if (g_strcmp0 (gtk_widget_get_name (ck_btn), "SHA-1") == 0) {
        hash_algo = GCRY_MD_SHA1;
        digest_size = SHA1_DIGEST_SIZE;
    }
    else if (g_strcmp0 (gtk_widget_get_name (ck_btn), "GOST94") == 0) {
        hash_algo = GCRY_MD_GOSTR3411_94;
        digest_size = GOST94_DIGEST_SIZE;
    }
    else if (g_strcmp0 (gtk_widget_get_name (ck_btn), "SHA-256") == 0) {
        hash_algo = GCRY_MD_SHA256;
        digest_size = SHA256_DIGEST_SIZE;
    }
    else if (g_strcmp0 (gtk_widget_get_name (ck_btn), "SHA3-256") == 0) {
        hash_algo = GCRY_MD_SHA3_256;
        digest_size = SHA3_256_DIGEST_SIZE;
    }
    else if (g_strcmp0 (gtk_widget_get_name (ck_btn), "SHA-384") == 0) {
        hash_algo = GCRY_MD_SHA384;
        digest_size = SHA384_DIGEST_SIZE;
    }
    else if (g_strcmp0 (gtk_widget_get_name (ck_btn), "SHA3-384") == 0) {
        hash_algo = GCRY_MD_SHA3_384;
        digest_size = SHA3_384_DIGEST_SIZE;
    }
    else if (g_strcmp0 (gtk_widget_get_name (ck_btn), "SHA-512") == 0) {
        hash_algo = GCRY_MD_SHA512;
        digest_size = SHA512_DIGEST_SIZE;
    }
    else if (g_strcmp0 (gtk_widget_get_name (ck_btn), "SHA3-512") == 0) {
        hash_algo = GCRY_MD_SHA3_512;
        digest_size = SHA3_512_DIGEST_SIZE;
    }
    else if (g_strcmp0 (gtk_widget_get_name (ck_btn), "WHIRLPOOL") == 0) {
        hash_algo = GCRY_MD_WHIRLPOOL;
        digest_size = WHIRLPOOL_DIGEST_SIZE;
    }

    gint i;
    for (i = 0; i < AVAILABLE_HASH_TYPE; i++) {
        if (g_strcmp0 (gtk_widget_get_name (ck_btn), gtk_widget_get_name (data->spinner[i])) == 0) {
            start_spinner (data->spinner[i]);
            break;
        }
    }

    thread_data->ck_btn = ck_btn;
    thread_data->digest_size = digest_size;
    thread_data->hash_algo = hash_algo;
    thread_data->widgets = data;

    g_thread_pool_push (data->thread_pool, thread_data, NULL);
}


static gpointer
exec_thread (gpointer pushed_data,
             gpointer user_data __attribute__((__unused__)))
{
    ThreadData *data = pushed_data;

    if (gtk_widget_get_sensitive (data->widgets->cancel_btn)) {
        gtk_widget_set_sensitive (data->widgets->cancel_btn, FALSE);
    }

    gchar *hash = get_file_hash (data->widgets->filename, data->hash_algo, data->digest_size);
    if (hash == NULL) {
        show_message_dialog (data->widgets->main_window, "Error during hash computation", GTK_MESSAGE_ERROR);
    }
    else {
        gint i;
        for (i = 0; i < AVAILABLE_HASH_TYPE; i++) {
            if (g_strcmp0 (gtk_widget_get_name (data->ck_btn), gtk_widget_get_name (data->widgets->hash_entry[i])) == 0) {
                gtk_entry_set_text (GTK_ENTRY (data->widgets->hash_entry[i]), hash);
                stop_spinner (data->widgets->spinner[i]);
                break;
            }
        }
    }

    if (!gtk_widget_get_sensitive (data->widgets->cancel_btn) && is_last_thread (data->widgets->thread_pool)) {
        gtk_widget_set_sensitive (data->widgets->cancel_btn, TRUE);
    }
    multiple_free (2, (gpointer *) &hash, (gpointer *) &data);
}


static gboolean
is_last_thread (GThreadPool *tp)
{
    if (g_thread_pool_get_num_threads (tp) == 1) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

/* TODO:
 * - deal with already toggled buttons (if already toggled then delete entry)
 * - add list of computed hashes like old gtkcrypto?
 */