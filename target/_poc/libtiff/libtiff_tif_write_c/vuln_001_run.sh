#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_write_c"

echo "[*] Generating PoC TIFF..."
python3 vuln_001_gen.py

echo "[*] Running tiffsplit with ASAN+UBSAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
UBSAN_OPTIONS="print_stacktrace=1:log_path=./ubsan.log" \
  /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit \
  vuln_001.tif /tmp/tiffsplit_out_ \
  > vuln_001_result.txt 2>&1 || true

echo "[*] Collecting ASAN/UBSAN output..."
for f in ./asan.log.* ./ubsan.log.*; do
  [ -f "$f" ] && {
    echo "--- $f ---" >> vuln_001_result.txt
    cat "$f"          >> vuln_001_result.txt
  } || true
done

echo "[*] Result:"
cat vuln_001_result.txt
