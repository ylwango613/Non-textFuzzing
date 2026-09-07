#!/bin/bash
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-csource_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"
INPUT="$POC_DIR/vuln_002.gdkp"
OUTPUT="$POC_DIR/vuln_002_out.gdkp"
RESULT="$POC_DIR/vuln_002_result.txt"
ASAN_LOG="$POC_DIR/asan_002.log"

echo "[*] Generating PoC input..."
python3 "$POC_DIR/vuln_002_gen.py"

echo "[*] Running binary with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  timeout 30 "$BINARY" "$INPUT" "$OUTPUT" > "$RESULT" 2>&1 || true

echo "[*] stdout/stderr:" >> "$RESULT"
echo "=== ASAN LOG ===" >> "$RESULT"
cat "${ASAN_LOG}"* 2>/dev/null >> "$RESULT" || echo "(no ASAN log)" >> "$RESULT"

echo "[*] Result written to $RESULT"
echo "--- Result summary ---"
head -60 "$RESULT"
