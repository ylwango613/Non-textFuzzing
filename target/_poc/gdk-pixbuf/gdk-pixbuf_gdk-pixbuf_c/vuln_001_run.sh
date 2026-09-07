#!/bin/bash
set -uo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"

cd "$POC_DIR"

# Generate the malicious file
python3 "$POC_DIR/vuln_001_gen.py"

# Clean old logs
rm -f "${POC_DIR}"/asan_001.log*

ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_001.log" \
  timeout 30 "$BINARY" \
    "$POC_DIR/vuln_001.gdkp" \
    "$POC_DIR/vuln_001_out.c" \
  > "$POC_DIR/vuln_001_result.txt" 2>&1
EXITCODE=$?

echo "Exit code: $EXITCODE" >> "$POC_DIR/vuln_001_result.txt"

# Show any ASAN logs
if ls "${POC_DIR}"/asan_001.log* 2>/dev/null | head -1 >/dev/null; then
    cat "${POC_DIR}"/asan_001.log* 2>/dev/null || true
fi
