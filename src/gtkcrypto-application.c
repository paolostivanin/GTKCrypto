#include <gcrypt.h>
#include "gtkcrypto-application.h"
#include "gtkcrypto-window.h"

#define APP_ID          "com.github.paolostivanin.GTKCrypto"
#define GCRYPT_MIN_VER  "1.7.0"
#define SECMEM_SIZE     32768

struct _GtkcryptoApplication {
    AdwApplication parent_instance;
};

G_DEFINE_TYPE (GtkcryptoApplication, gtkcrypto_application, ADW_TYPE_APPLICATION)


static void
gtkcrypto_application_activate (GApplication *app)
{
    GtkWindow *window = gtk_application_get_active_window (GTK_APPLICATION (app));
    if (window == NULL) {
        window = GTK_WINDOW (gtkcrypto_window_new (GTKCRYPTO_APPLICATION (app)));
    }
    gtk_window_present (window);
}


static void
gtkcrypto_application_startup (GApplication *app)
{
    G_APPLICATION_CLASS (gtkcrypto_application_parent_class)->startup (app);

    if (!gcry_check_version (GCRYPT_MIN_VER)) {
        g_critical ("The required version of GCrypt is %s or greater.", GCRYPT_MIN_VER);
        g_application_quit (app);
        return;
    }

    if (gcry_control (GCRYCTL_INIT_SECMEM, SECMEM_SIZE, 0)) {
        g_critical ("Couldn't initialize secure memory.");
        g_application_quit (app);
        return;
    }
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    GtkCssProvider *css_provider = gtk_css_provider_new ();
    gtk_css_provider_load_from_resource (css_provider,
                                         "/com/github/paolostivanin/GTKCrypto/gtkcrypto.css");
    gtk_style_context_add_provider_for_display (gdk_display_get_default (),
                                                GTK_STYLE_PROVIDER (css_provider),
                                                GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
}


static void
gtkcrypto_application_class_init (GtkcryptoApplicationClass *klass)
{
    GApplicationClass *app_class = G_APPLICATION_CLASS (klass);
    app_class->activate = gtkcrypto_application_activate;
    app_class->startup = gtkcrypto_application_startup;
}


static void
gtkcrypto_application_init (GtkcryptoApplication *self)
{
    (void)self;
}


GtkcryptoApplication *
gtkcrypto_application_new (void)
{
    return g_object_new (GTKCRYPTO_TYPE_APPLICATION,
                         "application-id", APP_ID,
                         NULL);
}
