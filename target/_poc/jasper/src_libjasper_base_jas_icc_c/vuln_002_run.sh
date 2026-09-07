#!/usr/bin/env bash
# Run script for VULN 002 - Heap buffer underwrite in jas_icctxt_input
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/jasper/src_libjasper_base_jas_icc_c"
IMGINFO="/data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo"
INPUT="${POC_DIR}/vuln_002.jp2"
RESULT="${POC_DIR}/vuln_002_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan.log"

echo "=== VULN 002 - Heap buffer underwrite in jas_icctxt_input ===" | tee "${RESULT}"
echo "Timestamp: $(date)" | tee -a "${RESULT}"
echo "" | tee -a "${RESULT}"

# Step 1: Generate the crafted JP2 input
echo "[1] Generating crafted JP2 input..." | tee -a "${RESULT}"
python3 "${POC_DIR}/vuln_002_gen.py" 2>&1 | tee -a "${RESULT}"
echo "" | tee -a "${RESULT}"

if [ ! -f "${INPUT}" ]; then
    echo "ERROR: Failed to generate ${INPUT}" | tee -a "${RESULT}"
    exit 1
fi

echo "[2] Running imginfo with ASAN..." | tee -a "${RESULT}"
echo "    Binary : ${IMGINFO}" | tee -a "${RESULT}"
echo "    Input  : ${INPUT}" | tee -a "${RESULT}"
echo "" | tee -a "${RESULT}"

# Step 2: Run imginfo with ASAN options
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
    "${IMGINFO}" \
    -f "${INPUT}" \
    >> "${RESULT}" 2>&1 || true

echo "" | tee -a "${RESULT}"
echo "[3] Checking ASAN/UBSAN logs..." | tee -a "${RESULT}"

# Step 3: Append ASAN/UBSAN output from log files
FOUND_ASAN=0
for f in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "${f}" ]; then
        echo "--- ASAN log: ${f} ---" | tee -a "${RESULT}"
        cat "${f}" | tee -a "${RESULT}"
        FOUND_ASAN=1
    fi
done

if [ "${FOUND_ASAN}" -eq 0 ]; then
    echo "    (No ASAN log files found)" | tee -a "${RESULT}"
fi

echo "" | tee -a "${RESULT}"
echo "=== Done ===" | tee -a "${RESULT}"
