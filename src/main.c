#include <glib/gi18n.h>
#include <locale.h>
#include "gtkcrypto-application.h"

int
main (int    argc,
      char **argv)
{
    setlocale (LC_ALL, "");
    bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
    bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
    textdomain (GETTEXT_PACKAGE);

    g_autoptr(GtkcryptoApplication) app = gtkcrypto_application_new ();
    return g_application_run (G_APPLICATION (app), argc, argv);
}
