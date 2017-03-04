#pragma once

#define HASH_ERR_CSS 101
#define HASH_OK_CSS 102

typedef struct _pango_data {
    PangoAttrList *attrs;
    PangoFontDescription *font_desc;
    PangoAttribute *attr;
} PangoData;

void set_css (gint css_type, GtkWidget *widget);

PangoData *get_pango_monospace_attr (void);

void pango_data_free (PangoData *data);