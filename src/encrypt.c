#include <gtk/gtk.h>
#include <gcrypt.h>

typedef struct header_metadata_t {
    guint8 *iv;
    guint8 *salt;
    gint algo;
    gint algo_mode;
} Metadata;


void
encrypt_file (const gchar *algo, const gchar *algo_mode)
{
    sleep (5);
    return;
}