#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/jhead/gpsinfo_c"

# Generate input if not present
[ -f vuln_002_input.jpg ] || python3 vuln_002_gen.py

echo "[*] Running jhead on vuln_002_input.jpg ..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/jhead/build_test/jhead -v vuln_002_input.jpg \
  > vuln_002_result.txt 2>&1 || true

echo "[*] jhead exited. Checking sanitizer logs ..."
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_002_result.txt || true
done

echo "[*] Result written to vuln_002_result.txt"
cat vuln_002_result.txt
