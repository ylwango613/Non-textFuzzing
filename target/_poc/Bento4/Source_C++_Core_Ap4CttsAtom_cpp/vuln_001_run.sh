#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4CttsAtom_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4="${POC_DIR}/vuln_001.mp4"
RESULT="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG="${POC_DIR}/asan.log"

echo "[*] Generating malicious MP4..."
python3 "${POC_DIR}/vuln_001_gen.py"

echo "[*] Running mp42aac with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
    "${BINARY}" "${MP4}" /dev/null \
    > "${RESULT}" 2>&1 || true

echo "[*] Collecting ASAN/UBSAN output..."
for f in "${ASAN_LOG}".*; do
    [ -f "$f" ] && cat "$f" >> "${RESULT}" && echo "" >> "${RESULT}"
done

echo "[*] Result saved to ${RESULT}"
grep -E "ERROR:|runtime error:|SUMMARY:" "${RESULT}" | head -20 || echo "[*] No ASAN/UBSAN error found in output"
