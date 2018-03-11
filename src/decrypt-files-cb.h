#pragma once

typedef struct decrypt_file_widgets_t {
    GtkWidget *main_window;
    GtkWidget *dialog;
    GtkWidget *entry_pwd;
    GtkWidget *ck_btn_delete;
    GtkWidget *cancel_btn;
    GtkWidget *ok_btn;
    GtkWidget *spinner;
    GtkWidget *message_label;
    GSList    *files_list;
    GThreadPool *thread_pool;
    guint running_threads;
    guint files_not_decrypted;
    guint source_id;
    gboolean first_run;
} DecryptWidgets;

typedef struct dec_thread_data_t {
    GMutex mutex;
    GtkWidget *dialog;
    GtkWidget *spinner;
    guint list_len;
    const gchar *pwd;
    gboolean delete_file;
    DecryptWidgets *widgets;
} ThreadData;

gpointer decrypt_file (const gchar *input_file_path, const gchar *pwd);
