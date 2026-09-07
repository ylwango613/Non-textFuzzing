#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4File_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4="${POC_DIR}/vuln_002.mp4"
RESULT="${POC_DIR}/vuln_002_result.txt"

# Step 1: generate the malicious MP4
python3 "${POC_DIR}/vuln_002_gen.py"

# Step 2: run the binary under ASAN
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan.log" \
    "${BINARY}" "${MP4}" /dev/null \
    > "${RESULT}" 2>&1 || true

# Step 3: append any ASAN log files
for f in "${POC_DIR}"/asan.log.*; do
    [ -f "$f" ] && cat "$f" >> "${RESULT}"
done
