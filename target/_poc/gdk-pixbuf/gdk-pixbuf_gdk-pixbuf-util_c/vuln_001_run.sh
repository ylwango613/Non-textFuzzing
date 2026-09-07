#!/bin/bash
set -x
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-util_c"
BIN="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"
IMG="${POC_DIR}/vuln_001.jpeg"
OUT="${POC_DIR}/vuln_001_out.c"

ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan.log" \
  timeout 30 "$BIN" "$IMG" "$OUT" \
  > "${POC_DIR}/vuln_001_result.txt" 2>&1 || true

echo "Exit code: $?"
echo "--- result ---"
cat "${POC_DIR}/vuln_001_result.txt"
echo "--- asan log ---"
cat "${POC_DIR}/asan.log"* 2>/dev/null || echo "(no asan log)"
