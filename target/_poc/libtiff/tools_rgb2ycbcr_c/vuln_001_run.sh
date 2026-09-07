#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/libtiff/tools_rgb2ycbcr_c"

# Generate the malicious TIFF if not already present
[ -f vuln_001.tif ] || python3 vuln_001_gen.py

echo "[*] Running rgb2ycbcr on vuln_001.tif ..."

ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/rgb2ycbcr \
  vuln_001.tif /tmp/rgb2ycbcr_out.tif \
  > vuln_001_result.txt 2>&1 || true

echo "[*] Checking for ASAN/UBSAN errors ..."
for f in ./asan.log.*; do
  [ -f "$f" ] && {
    echo "[*] Found ASAN log: $f"
    grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
      >> vuln_001_result.txt || true
  }
done

echo "[*] Result:"
cat vuln_001_result.txt
