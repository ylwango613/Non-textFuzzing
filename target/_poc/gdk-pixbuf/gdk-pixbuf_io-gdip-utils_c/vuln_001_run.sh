#!/bin/bash
# PoC runner for VULN_001: Heap OOB Read in gdip_bitmap_get_frame_delay
# NOTE: This vulnerability is Windows/GDI+ specific and CANNOT be triggered
# in this Linux build (io-gdip-utils.c is not compiled in).

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-utils_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"

echo "[*] Generating PoC GIF..."
python3 "$POC_DIR/vuln_001_gen.py"

echo "[*] Running gdk-pixbuf-pixdata against vuln_001.gif..."
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  timeout 30 "$BINARY" "$POC_DIR/vuln_001.gif" "$POC_DIR/vuln_001_out.c" \
  > "$POC_DIR/vuln_001_result.txt" 2>&1 || true

EXIT_CODE=$?
echo "Exit: $EXIT_CODE"
cat "$POC_DIR/vuln_001_result.txt"
