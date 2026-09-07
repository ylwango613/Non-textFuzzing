#!/bin/bash
# PoC runner for VULN 002: fpDiff() OOB Read via BitsPerSample=9 + Predictor=3
# NOTE: tiffsplit uses TIFFReadRawStrip/TIFFWriteRawStrip (bypass predictor),
# so fpDiff is not triggered. Expected outcome: SKIPPED / no crash.
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_predict_c"
TIFFSPLIT="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit"
RESULT="$POC_DIR/vuln_002_result.txt"

cd "$POC_DIR"

echo "=== VULN 002 PoC Run ===" | tee "$RESULT"
echo "Date: $(date)" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Generate the malicious TIFF if not already present
if [ ! -f "$POC_DIR/vuln_002.tif" ]; then
    echo "[*] Generating vuln_002.tif ..." | tee -a "$RESULT"
    python3 "$POC_DIR/vuln_002_gen.py" 2>&1 | tee -a "$RESULT"
else
    echo "[*] vuln_002.tif already exists, skipping generation." | tee -a "$RESULT"
fi

echo "" | tee -a "$RESULT"
echo "[*] Running tiffsplit on vuln_002.tif ..." | tee -a "$RESULT"

ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan_002.log" \
    "$TIFFSPLIT" "$POC_DIR/vuln_002.tif" /tmp/tiffsplit_002_out_ \
    >> "$RESULT" 2>&1 || true

echo "" | tee -a "$RESULT"
echo "[*] Checking for ASAN reports ..." | tee -a "$RESULT"
CRASH_FOUND=0
for f in "$POC_DIR"/asan_002.log.*; do
    if [ -f "$f" ]; then
        echo "[*] Found ASAN log: $f" | tee -a "$RESULT"
        if grep -qE "AddressSanitizer|ERROR:|runtime error:" "$f" 2>/dev/null; then
            echo "[!] ASAN error detected in $f" | tee -a "$RESULT"
            grep -E "AddressSanitizer|ERROR:|runtime error:|READ of size|WRITE of size|heap-buffer|stack-buffer" "$f" | head -30 | tee -a "$RESULT"
            CRASH_FOUND=1
        else
            echo "    (no ASAN errors in this log)" | tee -a "$RESULT"
        fi
    fi
done

echo "" | tee -a "$RESULT"
if [ "$CRASH_FOUND" -eq 1 ]; then
    echo "[RESULT] VERIFIED_CRASH" | tee -a "$RESULT"
    echo "VERIFIED_CRASH" > "$POC_DIR/vuln_002_status.txt"
else
    echo "[RESULT] No crash detected." | tee -a "$RESULT"
    echo "[INFO] tiffsplit uses TIFFReadRawStrip/TIFFWriteRawStrip which bypass" | tee -a "$RESULT"
    echo "[INFO] the predictor encoding path (PredictorEncodeRow -> fpDiff)." | tee -a "$RESULT"
    echo "[INFO] fpDiff is only reachable via TIFFWriteEncodedStrip." | tee -a "$RESULT"
    echo "[RESULT] SKIPPED - fpDiff not reachable through tiffsplit" | tee -a "$RESULT"
    echo "SKIPPED" > "$POC_DIR/vuln_002_status.txt"
fi

echo "" | tee -a "$RESULT"
echo "=== Done ===" | tee -a "$RESULT"
