#!/usr/bin/env bash
# VULN-001 run script: Integer Underflow in AP4_DecoderConfigDescriptor

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${SCRIPT_DIR}/vuln_001.mp4"
OUTPUT="${SCRIPT_DIR}/vuln_001_out.aac"
LOG="${SCRIPT_DIR}/vuln_001_run.log"

# Clear previous log
> "${LOG}"

echo "[*] Generating malicious MP4 (DecoderConfig directly in esds, no ES_Descriptor)..."
python3 "${SCRIPT_DIR}/vuln_001_gen.py" "${INPUT}" 2>&1 | tee -a "${LOG}"

echo "[*] Running mp42aac with ASAN/UBSAN options..."
export ASAN_OPTIONS="detect_odr_violation=0:halt_on_error=1:abort_on_error=1:symbolize=1:detect_leaks=0"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

set +e
"${BINARY}" "${INPUT}" "${OUTPUT}" >> "${LOG}" 2>&1
EXIT_CODE=$?
set -e

echo "[*] Exit code: ${EXIT_CODE}" | tee -a "${LOG}"

if grep -qE "ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)|runtime error:|SEGV|heap-buffer-overflow|stack-buffer-overflow|heap-use-after-free|SUMMARY: AddressSanitizer|AddressSanitizer:DEADLYSIGNAL" "${LOG}" 2>/dev/null; then
    echo "[!] SANITIZER ERROR DETECTED - CRASH CONFIRMED" | tee -a "${LOG}"
    cat "${LOG}"
    exit 2
elif [ "${EXIT_CODE}" -ne 0 ]; then
    echo "[!] Non-zero exit code ${EXIT_CODE} - possible crash (no ASAN message detected)" | tee -a "${LOG}"
    cat "${LOG}"
    exit 1
else
    echo "[-] Binary exited cleanly (exit code 0, no sanitizer error)" | tee -a "${LOG}"
    cat "${LOG}"
    exit 0
fi
