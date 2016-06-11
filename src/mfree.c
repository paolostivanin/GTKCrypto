#include <gtk/gtk.h>
#include <stdarg.h>
#include <gcrypt.h>

void
multiple_free (gint argc, gpointer *buf, ...)
{
    gint i = 0;
    va_list ptr;
    va_start (ptr, buf);
    while (i < argc) {
        if (*buf != NULL) {
            g_free (*buf);
            *buf = NULL;
        }
        buf = va_arg (ptr, gpointer *);
        i++;
    }
    va_end (ptr);
}


void multiple_gcry_free (gint argc, gpointer *buf, ...)
{
    gint i = 0;
    va_list ptr;
    va_start (ptr, buf);
    while (i < argc) {
        if (*buf != NULL) {
            gcry_free (*buf);
            *buf = NULL;
        }
        buf = va_arg (ptr, gpointer *);
        i++;
    }
    va_end (ptr);
}