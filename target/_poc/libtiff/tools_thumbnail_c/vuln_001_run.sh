#!/bin/bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/tools_thumbnail_c"
BINARY="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/thumbnail"
INPUT="${POC_DIR}/vuln_001.tif"
OUTPUT="/tmp/thumbnail_out_001.tif"
RESULT="${POC_DIR}/vuln_001_result.txt"

cd "${POC_DIR}"

# Generate the malicious TIFF if not already present
[ -f "${INPUT}" ] || python3 "${POC_DIR}/vuln_001_gen.py"

# Remove stale asan log files
rm -f "${POC_DIR}"/asan.log.*

# Run thumbnail with ASAN options; allow non-zero exit
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan.log" \
  "${BINARY}" "${INPUT}" "${OUTPUT}" > "${RESULT}" 2>&1 || true

# Collect any ASAN/UBSAN errors from log files
for f in "${POC_DIR}"/asan.log.*; do
    [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:|heap-buffer-overflow|SEGV" "$f" \
        >> "${RESULT}" || true
done

echo "--- Result ---"
cat "${RESULT}"
