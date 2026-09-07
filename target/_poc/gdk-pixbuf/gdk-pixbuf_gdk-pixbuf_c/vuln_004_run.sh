#!/bin/bash

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"

cd "$POC_DIR"

python3 "$POC_DIR/vuln_004_gen.py"

echo "Running with 30-second timeout..."

START=$(date +%s)

ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_004.log" \
  timeout 30 "$BINARY" \
    "$POC_DIR/vuln_004.gdkp" \
    "$POC_DIR/vuln_004_out.c" \
  > "$POC_DIR/vuln_004_result.txt" 2>&1
EXIT_CODE=$?

END=$(date +%s)
ELAPSED=$((END - START))

echo "Exit code: $EXIT_CODE (124 = killed by timeout)" >> "$POC_DIR/vuln_004_result.txt"
echo "Elapsed time: ${ELAPSED}s" >> "$POC_DIR/vuln_004_result.txt"

if [ $EXIT_CODE -eq 124 ]; then
    echo "CONFIRMED: Process killed by timeout after ${ELAPSED}s (infinite loop DoS verified)" >> "$POC_DIR/vuln_004_result.txt"
fi

if ls "${POC_DIR}"/asan_004.log.* >/dev/null 2>&1; then
    echo "--- ASAN log ---" >> "$POC_DIR/vuln_004_result.txt"
    cat "${POC_DIR}"/asan_004.log.* >> "$POC_DIR/vuln_004_result.txt"
fi

cat "$POC_DIR/vuln_004_result.txt"
