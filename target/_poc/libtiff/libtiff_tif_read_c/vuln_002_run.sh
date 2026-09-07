#!/bin/bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_read_c"
TIFFSPLIT="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit"

cd "$POC_DIR"

echo "[*] Generating vuln_002.tif ..."
python3 vuln_002_gen.py

echo "[*] Running tiffsplit on vuln_002.tif ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan.log" \
  "$TIFFSPLIT" vuln_002.tif /tmp/tiffsplit_out_ > vuln_002_result.txt 2>&1 || true

echo "[*] Collecting ASAN/UBSAN output ..."
for f in "${POC_DIR}"/asan.log.*; do
    [ -f "$f" ] && grep -E "AddressSanitizer|SEGV|ERROR:|runtime error:" "$f" \
        >> vuln_002_result.txt || true
done

echo "[*] Done. Results in vuln_002_result.txt"
cat vuln_002_result.txt
