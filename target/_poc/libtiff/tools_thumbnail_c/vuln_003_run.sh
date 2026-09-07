#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

THUMBNAIL=/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/thumbnail
TIF="$SCRIPT_DIR/vuln_003.tif"
RESULT="$SCRIPT_DIR/vuln_003_result.txt"

# Generate the malicious TIFF if needed
[ -f "$TIF" ] || python3 "$SCRIPT_DIR/vuln_003_gen.py"

# Clean previous results
rm -f "$RESULT" ./asan.log.*

echo "Running thumbnail on vuln_003.tif ..." | tee "$RESULT"
echo "Binary: $THUMBNAIL" | tee -a "$RESULT"
echo "Input:  $TIF" | tee -a "$RESULT"
echo "---" | tee -a "$RESULT"

ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan.log" \
  "$THUMBNAIL" "$TIF" /tmp/thumbnail_out_003.tif >> "$RESULT" 2>&1 || true

echo "---" | tee -a "$RESULT"
echo "Exit status collected. Checking ASAN/UBSAN logs..." | tee -a "$RESULT"

for f in "$SCRIPT_DIR"/asan.log.*; do
    [ -f "$f" ] || continue
    echo "=== $f ===" | tee -a "$RESULT"
    grep -E "AddressSanitizer|UBSAN|ERROR:|runtime error:|use-after|heap-buffer|stack-buffer|SEGV|uninitialized|wild pointer" "$f" \
        >> "$RESULT" 2>/dev/null || true
    head -60 "$f" >> "$RESULT" 2>/dev/null || true
done

echo "Done. See $RESULT"
