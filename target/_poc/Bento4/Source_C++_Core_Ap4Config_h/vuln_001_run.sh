#!/usr/bin/env bash
# PoC run script for Bento4 VULN 001 (AP4_CttsAtom entry_count integer overflow)
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MP4="${POC_DIR}/vuln_001.mp4"
RESULT="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG="${POC_DIR}/asan_001.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

# Step 1: generate the malicious MP4
echo "[*] Generating vuln_001.mp4 ..."
python3 "${POC_DIR}/vuln_001_gen.py"

# Step 2: run mp42aac under ASAN
echo "[*] Running mp42aac ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
    "${BINARY}" "${MP4}" /dev/null \
    > "${RESULT}" 2>&1 || true

echo "[*] mp42aac exited (crash expected — continuing)"

# Step 3: collect ASAN/UBSAN output from log files
echo "" >> "${RESULT}"
echo "=== ASAN/UBSAN log output ===" >> "${RESULT}"
for f in "${ASAN_LOG}".*; do
    if [ -f "${f}" ]; then
        echo "--- ${f} ---" >> "${RESULT}"
        grep -E "(ERROR|SUMMARY|AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|heap-buffer-overflow|heap-use-after-free|stack-buffer-overflow|bad_alloc|SEGV|abort|integer overflow|runtime error)" \
            "${f}" >> "${RESULT}" 2>/dev/null || true
        cat "${f}" >> "${RESULT}"
    fi
done

echo "[*] Results written to ${RESULT}"
