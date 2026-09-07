#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_dir_c"

# Generate the crafted TIFF if not already present
[ -f vuln_001.tif ] || python3 vuln_001_gen.py

# Run tiffsplit under ASan; allow non-zero exit (crash/error expected)
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit \
    vuln_001.tif /tmp/tiffsplit_out_ > vuln_001_result.txt 2>&1 || true

# Append any ASan findings to result file
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_001_result.txt || true
done
