#!/bin/bash
# PoC run script for VULN-004: Integer Underflow in extra_length (AP4_RtpPacket)
# CWE-191 Integer Underflow → CWE-834 Excessive Iteration
# File: Ap4RtpHint.cpp, lines 222-246

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4HintTrackReader_cpp"
MP4_FILE="${POC_DIR}/vuln_004.mp4"
RESULT_FILE="${POC_DIR}/vuln_004_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan_004.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

cd "${POC_DIR}"

# Step 1: Generate the malicious MP4
echo "[*] Generating vuln_004.mp4 ..."
python3 vuln_004_gen.py

echo "" > "${RESULT_FILE}"

# Step 2: Run mp42aac with ASAN options
echo "[*] Running mp42aac (with timeout 30s) ..."
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
