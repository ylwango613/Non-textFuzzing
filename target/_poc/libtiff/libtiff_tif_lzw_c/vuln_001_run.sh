#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_lzw_c"

# Regenerate PoC TIFF if not present
[ -f vuln_001.tif ] || python3 vuln_001_gen.py

# NOTE: tiffsplit uses TIFFReadRawStrip (raw copy) and does NOT call
# LZWPreDecode. The vulnerability trigger path requires TIFFReadEncodedStrip.
# tiffinfo -D -d does call TIFFReadEncodedStrip → TIFFFillStrip →
# TIFFStartStrip → LZWPreDecode → OOB Read at rawdata[1].

# --- Primary: tiffsplit (as specified in the task) ---
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit \
  vuln_001.tif /tmp/tiffsplit_out_ > vuln_001_result.txt 2>&1 || true

# --- Secondary: tiffinfo -D -d (triggers the actual LZWPreDecode OOB) ---
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffinfo \
  -D -d vuln_001.tif >> vuln_001_result.txt 2>&1 || true

# Collect ASAN reports
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_001_result.txt || true
done
