#!/bin/bash
# vuln_002_run.sh — PoC runner for VULN 002 (gtStripContig heap OOB read)
# NOTE: tiffsplit does NOT call TIFFRGBAImage APIs; this bug is SKIPPED
#       for tiffsplit. The script still runs tiffsplit for reference.
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_getimage_c"
TIFFSPLIT="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit"
TIF="$POC_DIR/vuln_002.tif"
RESULT="$POC_DIR/vuln_002_result.txt"

cd "$POC_DIR"

[ -f "$TIF" ] || python3 vuln_002_gen.py

echo "=== VULN 002 — tiffsplit run ===" > "$RESULT"
echo "TIF: $TIF" >> "$RESULT"
echo "" >> "$RESULT"

ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  "$TIFFSPLIT" "$TIF" /tmp/tiffsplit_out_002_ >> "$RESULT" 2>&1 || true

echo "" >> "$RESULT"
echo "=== ASAN log ===" >> "$RESULT"
for f in "$POC_DIR"/asan.log.*; do
    [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
        >> "$RESULT" || true
done

echo "" >> "$RESULT"
echo "=== NOTE ===" >> "$RESULT"
echo "tiffsplit calls cpStrips() (raw strip copy) and NEVER calls" >> "$RESULT"
echo "TIFFRGBAImageBegin / TIFFRGBAImageGet / gtStripContig." >> "$RESULT"
echo "The VULN 002 code path is therefore NOT reachable via tiffsplit." >> "$RESULT"
echo "Status: SKIPPED" >> "$RESULT"

cat "$RESULT"
