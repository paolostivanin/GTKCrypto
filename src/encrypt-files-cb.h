#pragma once

typedef struct encrypt_file_widgets_t {
    GtkWidget *main_window;
    GtkWidget *dialog;
    GtkWidget *entry_pwd;
    GtkWidget *entry_pwd_retype;
    GtkWidget *cancel_btn;
    GtkWidget *ok_btn;
    GSList *radio_btns_algo_list;
    GSList *radio_btns_mode_list;
    GtkWidget *header_bar_menu;
    GtkWidget *spinner;
    GtkWidget *message_label;
    GSList    *files_list;
    GThreadPool *thread_pool;
    guint running_threads;
    guint files_not_encrypted;
    guint source_id;
    gboolean first_run;
} EncryptWidgets;

typedef struct enc_thread_data_t {
    GMutex mutex;
    GtkWidget *dialog;
    GtkWidget *spinner;
    guint list_len;
    const gchar *algo_btn_name;
    const gchar *algo_mode_btn_name;
    const gchar *pwd;
    EncryptWidgets *widgets;
} ThreadData;

gpointer encrypt_file (const gchar *input_file_path, const gchar *pwd, const gchar *algo, const gchar *algo_mode);