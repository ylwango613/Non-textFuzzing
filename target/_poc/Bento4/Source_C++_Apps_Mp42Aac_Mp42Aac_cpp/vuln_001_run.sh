#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Apps_Mp42Aac_Mp42Aac_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${POC_DIR}/vuln_001.mp4"
OUTPUT="/dev/null"
RESULT="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan.log"

# Step 1: generate the malicious MP4
echo "[*] Generating vuln_001.mp4 ..."
python3 "${POC_DIR}/vuln_001_gen.py"

# Step 2: run the target binary under ASAN
echo "[*] Running mp42aac on vuln_001.mp4 ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
    "${BINARY}" "${INPUT}" "${OUTPUT}" \
    > "${RESULT}" 2>&1 || true

# Step 3: collect ASAN / UBSAN output from log shards
echo "" >> "${RESULT}"
echo "=== ASAN/UBSAN log output ===" >> "${RESULT}"
found_asan=0
for log_file in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "${log_file}" ]; then
        echo "--- ${log_file} ---" >> "${RESULT}"
        cat "${log_file}" >> "${RESULT}"
        found_asan=1
    fi
done

if [ "${found_asan}" -eq 0 ]; then
    echo "(no asan.log.* files found)" >> "${RESULT}"
fi

# Step 4: print summary to stdout
echo "[*] Result saved to: ${RESULT}"
echo ""
echo "=== Key findings ==="
if grep -qiE "ERROR: (AddressSanitizer|UBSan|sanitizer)|heap-buffer-overflow|stack-buffer-overflow|use-after-free|SEGV|runtime error" "${RESULT}" 2>/dev/null; then
    echo "[!] CRASH / SANITIZER ERROR DETECTED"
    grep -iE "ERROR: (AddressSanitizer|UBSan|sanitizer)|heap-buffer-overflow|stack-buffer-overflow|use-after-free|SEGV|runtime error" "${RESULT}" | head -20
else
    echo "[-] No obvious sanitizer error found in result.txt"
fi
