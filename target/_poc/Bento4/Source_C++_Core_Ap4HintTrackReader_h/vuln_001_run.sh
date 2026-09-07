#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4HintTrackReader_h"
MP4_FILE="${POC_DIR}/vuln_001.mp4"
RESULT_FILE="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "=== VULN 001 PoC Run ===" > "${RESULT_FILE}"
echo "Date: $(date)" >> "${RESULT_FILE}"
echo "" >> "${RESULT_FILE}"

# Step 1: Generate the crafted MP4
echo "[*] Generating crafted MP4..." | tee -a "${RESULT_FILE}"
python3 "${POC_DIR}/vuln_001_gen.py" 2>&1 | tee -a "${RESULT_FILE}"
echo "" >> "${RESULT_FILE}"

if [ ! -f "${MP4_FILE}" ]; then
    echo "[-] MP4 generation failed. Aborting." | tee -a "${RESULT_FILE}"
    exit 1
fi

echo "[*] MP4 file: ${MP4_FILE} ($(wc -c < "${MP4_FILE}") bytes)" | tee -a "${RESULT_FILE}"
echo "" >> "${RESULT_FILE}"

# Step 2: Run mp42aac with ASAN options
echo "[*] Running mp42aac with ASAN enabled..." | tee -a "${RESULT_FILE}"
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
    "${BINARY}" \
    "${MP4_FILE}" \
    /dev/null \
    >> "${RESULT_FILE}" 2>&1 || true

echo "" >> "${RESULT_FILE}"
echo "[*] mp42aac exited." >> "${RESULT_FILE}"
echo "" >> "${RESULT_FILE}"

# Step 3: Grep ASAN log files for errors
echo "[*] Checking ASAN log files..." | tee -a "${RESULT_FILE}"
ASAN_FOUND=0
for log in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "${log}" ]; then
        echo "--- ${log} ---" >> "${RESULT_FILE}"
        cat "${log}" >> "${RESULT_FILE}"
        echo "" >> "${RESULT_FILE}"
        # Check for relevant ASAN error keywords
        if grep -qiE "ERROR:|SEGV|heap-buffer-overflow|null.*dereference|stack-buffer|use-after-free|READ|WRITE" "${log}" 2>/dev/null; then
            ASAN_FOUND=1
        fi
    fi
done

if [ "${ASAN_FOUND}" -eq 0 ]; then
    echo "[*] No ASAN crash detected in log files." >> "${RESULT_FILE}"
    echo "" >> "${RESULT_FILE}"
    # Also check if any asan.log files exist at all
    if ! ls "${ASAN_LOG_PREFIX}".* 2>/dev/null | head -1 | grep -q .; then
        echo "[*] No ASAN log files were created." >> "${RESULT_FILE}"
    fi
fi

echo "" >> "${RESULT_FILE}"
echo "=== Done ===" >> "${RESULT_FILE}"

echo "[*] Result written to ${RESULT_FILE}"
