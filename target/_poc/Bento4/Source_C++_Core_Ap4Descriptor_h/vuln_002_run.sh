#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Descriptor_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${POC_DIR}/vuln_002.mp4"
RESULT="${POC_DIR}/vuln_002_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan.log"

# ── Step 1: Generate the malicious MP4 ──────────────────────────────────────
echo "[*] Generating malicious MP4..."
python3 "${POC_DIR}/vuln_002_gen.py"
echo "[*] Generation complete: ${INPUT}"

# ── Step 2: Run mp42aac with ASAN ───────────────────────────────────────────
echo "[*] Running mp42aac with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
  "${BINARY}" \
  "${INPUT}" \
  /dev/null \
  > "${RESULT}" 2>&1 || true

echo "[*] mp42aac finished (exit status ignored)"

# ── Step 3: Collect ASAN/UBSAN output ────────────────────────────────────────
echo "[*] Checking ASAN log files..."
found_error=0
for log in "${ASAN_LOG_PREFIX}".* ; do
    if [[ -f "${log}" ]]; then
        echo "[*] Found ASAN log: ${log}"
        if grep -qE "ERROR|SUMMARY|runtime error|heap-buffer-overflow|stack-buffer-overflow|use-after-free|SEGV|AddressSanitizer|undefined|integer overflow|bad_alloc|allocation-size-too-big|allocation failed" "${log}" 2>/dev/null; then
            echo "[!] ASAN/UBSAN error detected in ${log}"
            echo "--- ASAN log: ${log} ---" >> "${RESULT}"
            cat "${log}" >> "${RESULT}"
            found_error=1
        else
            echo "[*] No recognized ASAN error pattern in ${log}"
            echo "--- ASAN log (no error pattern): ${log} ---" >> "${RESULT}"
            cat "${log}" >> "${RESULT}"
        fi
    fi
done

# Also check result.txt itself for crash indicators
if grep -qE "Segmentation fault|Aborted|AddressSanitizer|UndefinedBehaviorSanitizer|bad_alloc|terminate" "${RESULT}" 2>/dev/null; then
    echo "[!] Crash/error indicator found in result.txt"
    found_error=1
fi

echo "[*] Result written to: ${RESULT}"
echo "[*] found_error=${found_error}"
