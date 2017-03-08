#pragma once

#define AVAILABLE_ALGO 6        // AES256, BLOWFISH, CAMELLIA256, CAST5, SERPENT256, TWOFISH
#define AVAILABLE_ALGO_MODE 2   // CBC, CTR

typedef struct encrypt_file_widgets_t {
    gboolean multi_files;
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
    GSList *files_list;
    gchar *filename;
    GThread *enc_thread;
} EncryptWidgets;

typedef struct enc_thread_data_t {
    GtkWidget *dialog;
    GtkWidget *spinner;
    GtkWidget *message_label;
    const gchar *algo_btn_name;
    const gchar *algo_mode_btn_name;
    const gchar *filename;
    const gchar *pwd;
} ThreadData;

void encrypt_single_file_dialog (EncryptWidgets *);

void encrypt_multiple_files_dialog (EncryptWidgets *);

void do_dialog (EncryptWidgets *);

void do_header_bar (GtkWidget *dialog, EncryptWidgets *);

void do_entry_widgets (EncryptWidgets *);

GtkWidget *create_hbox (EncryptWidgets *);

GtkWidget *create_popover (GtkWidget *parent, GtkPositionType pos, gpointer user_data);

GtkWidget *get_final_box_layout (EncryptWidgets *);

gboolean check_pwd (GtkWidget *main_window, GtkWidget *entry, GtkWidget *retype_entry);

void entry_activated_cb (GtkWidget *entry, gpointer user_data);

void prepare_single_encryption (const gchar *algo, const gchar *algo_mode, EncryptWidgets *);

void prepare_multi_encryption (const gchar *algo, const gchar *algo_mode, EncryptWidgets *);

gpointer encrypt_file (const gchar *input_file_path, const gchar *pwd, const gchar *algo, const gchar *algo_mode);