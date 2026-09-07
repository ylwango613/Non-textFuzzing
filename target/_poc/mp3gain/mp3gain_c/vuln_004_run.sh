#!/bin/bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/mp3gain/mp3gain_c"
BINARY="/data/ylwang/non-textfuzz/target/mp3gain/build_test/mp3gain"
MP3="${POC_DIR}/vuln_004.mp3"
RESULT="${POC_DIR}/vuln_004_result.txt"

cd "${POC_DIR}"

# Generate the malicious MP3 if not already present
if [ ! -f "${MP3}" ]; then
    echo "[*] Generating vuln_004.mp3 ..."
    python3 "${POC_DIR}/vuln_004_gen.py"
fi

echo "[*] Running mp3gain against vuln_004.mp3 ..."

# ASAN options: log to file, do not abort early so log is flushed
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan.log:detect_stack_use_after_return=1" \
    "${BINARY}" "${MP3}" > "${RESULT}" 2>&1 || true

echo "[*] mp3gain exited"

# Collect any ASAN reports into result file
FOUND_ASAN=0
for f in "${POC_DIR}"/asan.log.*; do
    if [ -f "${f}" ]; then
        echo "=== ASAN log: ${f} ===" >> "${RESULT}"
        cat "${f}" >> "${RESULT}"
        FOUND_ASAN=1
    fi
done

# Also check stderr/stdout for crash indicators
if grep -qE "AddressSanitizer|ERROR:|runtime error:|SEGV|Aborted|stack.buffer.overflow|global.buffer.overflow|heap.buffer.overflow" "${RESULT}" 2>/dev/null; then
    echo "[!] CRASH / SANITIZER ERROR DETECTED -- see ${RESULT}"
    exit 1
elif [ "${FOUND_ASAN}" -eq 1 ]; then
    echo "[!] ASAN log found but no explicit error pattern matched -- review ${RESULT}"
    exit 1
else
    echo "[*] No crash detected in output -- review ${RESULT} manually"
    exit 0
fi
