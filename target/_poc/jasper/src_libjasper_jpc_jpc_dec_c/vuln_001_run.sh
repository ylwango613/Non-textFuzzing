#!/usr/bin/env bash
# vuln_001_run.sh - Run PoC for JasPer VULN 001 (jpc_dec_tileinit prcwidthexpn=0)
# Trigger: COD Scod bit0=1 with prcsize[rlvlno=1]=0x00 => prcwidthexpn=0 => cbgwidthexpn=-1
# Bug: "shift exponent -1 is negative" UB at jpc_dec.c:851-936 (UBSAN-confirmed).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMGINFO="/data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo"
POC_JP2="${SCRIPT_DIR}/vuln_001.jp2"
ASAN_LOG_PREFIX="${SCRIPT_DIR}/asan.log"
RESULT_FILE="${SCRIPT_DIR}/result.txt"

echo "[*] Step 1: Generating PoC JP2 file..."
python3 "${SCRIPT_DIR}/vuln_001_gen.py"

echo "[*] Step 2: Running imginfo with ASAN+UBSAN options..."
export ASAN_OPTIONS="log_path=${ASAN_LOG_PREFIX}:halt_on_error=0:detect_leaks=0"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0"

set +e
OUTPUT=$("${IMGINFO}" -f "${POC_JP2}" 2>&1)
EXIT_CODE=$?
set -e

echo "${OUTPUT}"
echo "[*] imginfo exit code: ${EXIT_CODE}"

echo "[*] Step 3: Checking for UB/ASAN errors..."
UBSAN_HIT=0
ASAN_FOUND=0

# Check UBSAN errors in output (printed to stderr)
if echo "${OUTPUT}" | grep -q "runtime error: shift exponent"; then
    UBSAN_HIT=1
    echo "[*] UBSAN shift-out-of-bounds detected in output"
fi

# Check ASAN logs
for log_file in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "${log_file}" ]; then
        echo "[*] Found ASAN log: ${log_file}"
        cat "${log_file}"
        ASAN_FOUND=1
    fi
done

# Determine status
if [ "${UBSAN_HIT}" -eq 1 ] || [ "${ASAN_FOUND}" -eq 1 ] || [ "${EXIT_CODE}" -ne 0 ]; then
    STATUS="VERIFIED_CRASH"
else
    STATUS="UNVERIFIED"
fi

echo ""
echo "[*] Result: ${STATUS}"
printf '%s\n' "${STATUS}" > "${RESULT_FILE}"

# Append key UBSAN findings to result.txt
if [ "${UBSAN_HIT}" -eq 1 ]; then
    echo "--- UBSAN output (shift-out-of-bounds) ---" >> "${RESULT_FILE}"
    echo "${OUTPUT}" | grep "runtime error" | head -5 >> "${RESULT_FILE}" || true
fi

if [ "${ASAN_FOUND}" -eq 1 ]; then
    echo "--- ASAN output ---" >> "${RESULT_FILE}"
    for log_file in "${ASAN_LOG_PREFIX}".*; do
        [ -f "${log_file}" ] && grep -E "(ERROR|SUMMARY|assertion)" "${log_file}" >> "${RESULT_FILE}" 2>/dev/null || true
    done
fi

echo "[*] Result written to ${RESULT_FILE}"
