#!/bin/bash
# vuln_002_run.sh - Run PoC for VULN 002 (NULL ptr deref via g_try_malloc in io-gdip-utils.c)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_PY="$SCRIPT_DIR/vuln_002_gen.py"
INPUT="$SCRIPT_DIR/vuln_002.bmp"
OUTPUT="$SCRIPT_DIR/vuln_002_out.c"
RESULT="$SCRIPT_DIR/vuln_002_result.txt"
ASAN_LOG="$SCRIPT_DIR/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"

echo "[vuln_002_run] Generating crafted BMP..."
python3 "$GEN_PY" "$INPUT"

echo "[vuln_002_run] Running binary: $BINARY"
echo "[vuln_002_run] Input:  $INPUT"
echo "[vuln_002_run] Output: $OUTPUT"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "$BINARY" "$INPUT" "$OUTPUT" > "$RESULT" 2>&1 || true

EXIT_CODE=$?
echo "Exit code: $EXIT_CODE" >> "$RESULT"

echo "[vuln_002_run] Done. Exit code: $EXIT_CODE"
echo "[vuln_002_run] Result saved to: $RESULT"

# Check for ASAN output
if ls "${ASAN_LOG}".* 2>/dev/null | grep -q .; then
    echo "[vuln_002_run] ASAN log files found:"
    ls "${ASAN_LOG}".*
    cat "${ASAN_LOG}".* >> "$RESULT"
else
    echo "[vuln_002_run] No ASAN log files produced."
fi
