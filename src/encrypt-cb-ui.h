#pragma once

#define AVAILABLE_ALGO 6        // AES256, BLOWFISH, CAMELLIA256, CAST5, SERPENT256, TWOFISH
#define AVAILABLE_ALGO_MODE 2   // CBC, CTR

typedef struct encrypt_file_widgets_t {
    GtkWidget *main_window;
    GtkWidget *dialog;
    GtkWidget *entry_pwd;
    GtkWidget *entry_pwd_retype;
    GtkWidget *cancel_btn;
    GtkWidget *ok_btn;
    GtkWidget *radio_button_algo[AVAILABLE_ALGO];
    GtkWidget *radio_button_algo_mode[AVAILABLE_ALGO_MODE];
    GtkWidget *header_bar_menu;
    GtkWidget *spinner;
    GtkWidget *message_label;
    GSList    *files_list;
    GThreadPool *thread_pool;
    guint running_threads;
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

void do_dialog (EncryptWidgets *);

void do_header_bar (GtkWidget *dialog, EncryptWidgets *);

void do_entry_widgets (EncryptWidgets *);

GtkWidget *create_hbox (EncryptWidgets *);

GtkWidget *create_popover (GtkWidget *parent, GtkPositionType pos, gpointer user_data);

GtkWidget *get_final_box_layout (EncryptWidgets *);

gpointer encrypt_file (const gchar *input_file_path, const gchar *pwd, const gchar *algo, const gchar *algo_mode);