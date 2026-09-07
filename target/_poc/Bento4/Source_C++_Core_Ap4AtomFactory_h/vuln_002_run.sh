#!/bin/bash
set -e
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_h"

echo "[*] Generating PoC MP4..."
python3 "$POC_DIR/vuln_002_gen.py"

echo "[*] Running mp42aac against PoC..."
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  "$POC_DIR/vuln_002.mp4" /dev/null \
  > "$POC_DIR/vuln_002_result.txt" 2>&1 || true

# collect asan log fragments
for f in "$POC_DIR"/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> "$POC_DIR/vuln_002_result.txt" || true
done

echo "Done" >> "$POC_DIR/vuln_002_result.txt"
echo "[*] Results saved to $POC_DIR/vuln_002_result.txt"
