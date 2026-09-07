#!/bin/bash
# PoC runner for VULN 001 - AP4_Stz2Atom Integer Overflow -> Heap Buffer Over-read

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_cpp"
MP4_FILE="${POC_DIR}/vuln_001.mp4"
RESULT_FILE="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

# Step 1: Generate the malicious MP4
echo "[*] Generating malicious MP4..."
python3 "${POC_DIR}/vuln_001_gen.py"

# Step 2: Run mp42aac with ASAN logging
echo "[*] Running mp42aac on malicious MP4..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
  "${BINARY}" \
  "${MP4_FILE}" \
  /dev/null \
  > "${RESULT_FILE}" 2>&1 || true

# Step 3: Collect ASAN/UBSAN errors from log files
echo "[*] Collecting ASAN/UBSAN output..."
for f in "${ASAN_LOG_PREFIX}".*; do
  [ -f "$f" ] && grep -E "ERROR:|runtime error:|SUMMARY:" "$f" >> "${RESULT_FILE}" || true
done

echo "[*] Done. Results in ${RESULT_FILE}"
