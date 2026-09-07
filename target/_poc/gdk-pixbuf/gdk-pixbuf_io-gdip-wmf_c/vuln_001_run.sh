#!/bin/bash
BINARY=/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata
POC_DIR=/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-wmf_c

# Generate the malicious file
python3 "$POC_DIR/vuln_001_gen.py"

# Run the binary with ASAN
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  "$BINARY" "$POC_DIR/vuln_001.gif" "$POC_DIR/vuln_001_out.c" \
  > "$POC_DIR/vuln_001_result.txt" 2>&1 || true

echo "Exit code: $?"
cat "$POC_DIR/vuln_001_result.txt"
