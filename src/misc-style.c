#include <gtk/gtk.h>
#include "misc-style.h"


void
set_css (gint css_type, GtkWidget *widget)
{
    const gchar *data = NULL;

    GtkCssProvider *css = gtk_css_provider_new ();

    if (css_type == HASH_ERR_CSS) {
        data = "#file1_he_name, #file2_he_name { font-family: \"monospace\"; background: #FA5858;}";
    } else if (css_type == HASH_OK_CSS) {
        data = "#file1_he_name, #file2_he_name {font-family: \"monospace\"; background: limegreen;}";
    }
    gtk_css_provider_load_from_string (css, data);

    gtk_style_context_add_provider_for_display (gtk_widget_get_display (widget),
                                                GTK_STYLE_PROVIDER (css),
                                                GTK_STYLE_PROVIDER_PRIORITY_USER);
    g_object_unref (css);
}


PangoData *
get_pango_monospace_attr ()
{
    PangoData *pango_data = g_new0 (PangoData, 1);

    pango_data->attrs = pango_attr_list_new ();
    pango_data->font_desc = pango_font_description_new ();
    pango_font_description_set_family (pango_data->font_desc, "monospace");

    pango_data->attr = pango_attr_font_desc_new (pango_data->font_desc);
    pango_attr_list_insert (pango_data->attrs, pango_data->attr);

    return pango_data;
}


void
pango_data_free (PangoData *data)
{
    pango_font_description_free (data->font_desc);
    pango_attr_list_unref (data->attrs);
    g_free (data);
}
