#!/bin/bash
set -euo pipefail

POCDIR="/data/ylwang/non-textfuzz/target/_poc/jhead/jpgfile_c"
JHEAD="/data/ylwang/non-textfuzz/target/jhead/build_test/jhead"

cd "$POCDIR"

# Generate the crafted JPEG if not already present
[ -f vuln_001_input.jpg ] || python3 vuln_001_gen.py

# Run jhead under ASAN+UBSAN (binary already instrumented)
ASAN_OPTIONS="abort_on_error=0:log_path=${POCDIR}/asan.log" \
UBSAN_OPTIONS="print_stacktrace=1:log_path=${POCDIR}/ubsan.log" \
  "$JHEAD" vuln_001_input.jpg > vuln_001_result.txt 2>&1 || true

# Append any ASAN/UBSAN findings to result file
for f in "${POCDIR}"/asan.log.*; do
    [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
        >> vuln_001_result.txt 2>/dev/null || true
done
for f in "${POCDIR}"/ubsan.log.*; do
    [ -f "$f" ] && grep -E "runtime error:|SUMMARY:" "$f" \
        >> vuln_001_result.txt 2>/dev/null || true
done

echo "--- Run complete. Output in vuln_001_result.txt ---"
cat vuln_001_result.txt
