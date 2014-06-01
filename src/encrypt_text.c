#include <gtk/gtk.h>
#include <glib.h>
#include <gcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glib/gi18n.h>
#include <locale.h>
#include <libintl.h>
#include <libnotify/notify.h>
#include "polcrypt.h"

static void send_notification(const gchar *, const gchar *);

gint encrypt_text(struct widget_t *Widget){
	
	send_notification("PolCrypt", "Tutto ok, farò qualcosa");
	
	return 0;
}

static void send_notification(const gchar *title, const gchar *message){
	NotifyNotification *n;
    notify_init("org.gtk.polcrypt");
    n = notify_notification_new (title, message, NULL);
    notify_notification_set_timeout(n, 3000);
    if (!notify_notification_show (n, NULL)) {
		g_error("Failed to send notification.\n");
        g_thread_exit((gpointer)-1);
	}
	g_object_unref(G_OBJECT(n));
}
