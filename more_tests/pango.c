#include<stdio.h>
#include<cairo.h>
#include<pango/pangocairo.h>

#define IMAGE_WIDTH  650
#define IMAGE_HEIGHT 150

#define TEXT "HELLO WORLD"
#define FONT "MizuFontAlphabet Normal 40"

/*
 * $ gcc $(pkg-config pangocairo cairo --cflags --libs) file.c
 */


int main(int argc , char** argv) {

    cairo_surface_t *surface;
    cairo_t *cr;

    PangoLayout *layout;
    PangoFontDescription *desc;
    PangoRectangle extents;

    surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, IMAGE_WIDTH, IMAGE_HEIGHT);
    cr      = cairo_create(surface);

    cairo_rectangle(cr, 0, 0, IMAGE_WIDTH, IMAGE_HEIGHT);
    cairo_set_source_rgb(cr, 0, 0, 0);
    cairo_fill(cr);
    cairo_stroke(cr);

    printf("first part\n");

    /* the font is needed to be installed in fonts directory */
    layout  = pango_cairo_create_layout(cr);
    pango_layout_set_text(layout, TEXT, -1);
    desc    = pango_font_description_from_string(FONT);
    pango_layout_set_font_description(layout, desc);
    pango_font_description_free (desc);

    printf("second part\n");

    pango_layout_get_pixel_extents(layout, NULL, &extents);
    int x   = (int) (IMAGE_WIDTH - extents.width) / 2;
    int y   = (int) (IMAGE_HEIGHT - extents.height) / 2;

    printf("second part 1\n");
    cairo_set_source_rgb(cr, 0.33, 0.55, 0.88);
    printf("second part 2\n");
    cairo_move_to(cr, x, y);
    printf("second part 3\n");
    pango_cairo_show_layout(cr, layout);

    printf("third part\n");

    g_object_unref(layout);

    printf("fourth part\n");

    cairo_surface_write_to_png(surface, "image.png");

    printf("fifth part\n");

    cairo_destroy(cr);
    cairo_surface_destroy(surface);

    return(0);
}

