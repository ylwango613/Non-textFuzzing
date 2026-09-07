#!/bin/bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"

cd "$POC_DIR"

python3 "$POC_DIR/vuln_002_gen.py"

ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_002.log" \
  timeout 30 "$BINARY" \
    "$POC_DIR/vuln_002.gdkp" \
    "$POC_DIR/vuln_002_out.c" \
  > "$POC_DIR/vuln_002_result.txt" 2>&1 || true

echo "Exit code: $?" >> "$POC_DIR/vuln_002_result.txt"

if ls "${POC_DIR}"/asan_002.log* 2>/dev/null | head -1; then
    cat "${POC_DIR}"/asan_002.log* 2>/dev/null || true
fi
