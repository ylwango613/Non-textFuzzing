#!/usr/bin/env bash
# PoC runner for VULN 001: AP4_CttsAtom integer overflow
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${POC_DIR}/vuln_001.mp4"
OUTPUT="${POC_DIR}/vuln_001_out.aac"
LOG_PREFIX="${POC_DIR}/asan.log"

echo "[*] Step 1: Generate PoC input"
python3 "${POC_DIR}/vuln_001_gen.py"

echo "[*] Step 2: Run mp42aac under ASAN"
export ASAN_OPTIONS="halt_on_error=1:abort_on_error=1:log_path=${LOG_PREFIX}:detect_leaks=0"

set +e
"${BINARY}" "${INPUT}" "${OUTPUT}" 2>&1
EXIT_CODE=$?
set -e

echo "[*] Exit code: ${EXIT_CODE}"

# Collect any ASAN log files
ASAN_LOGS=$(ls "${LOG_PREFIX}".* 2>/dev/null || true)
if [ -n "${ASAN_LOGS}" ]; then
    echo "[+] ASAN log(s) found:"
    for log in ${ASAN_LOGS}; do
        echo "    ${log}"
        head -60 "${log}"
    done
else
    echo "[-] No ASAN log files found (may have crashed without ASAN, or ASAN not compiled in)"
fi

# Determine status
if [ "${EXIT_CODE}" -ne 0 ]; then
    echo "[+] CRASH / ABNORMAL EXIT DETECTED (exit code ${EXIT_CODE})"
    STATUS="VERIFIED_CRASH"
else
    echo "[-] Process exited cleanly — vulnerability may not have triggered"
    STATUS="UNVERIFIED"
fi

echo "${STATUS}" > "${POC_DIR}/vuln_001_status.txt"
echo "Exit code: ${EXIT_CODE}" >> "${POC_DIR}/vuln_001_status.txt"
if [ -n "${ASAN_LOGS}" ]; then
    echo "ASAN logs: ${ASAN_LOGS}" >> "${POC_DIR}/vuln_001_status.txt"
fi

echo "[*] Done. Status: ${STATUS}"
