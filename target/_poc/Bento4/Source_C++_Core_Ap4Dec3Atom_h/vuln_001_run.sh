#!/bin/bash
# VULN-001 PoC runner: Heap Over-Read in AP4_Dec3Atom Constructor
set -e

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Dec3Atom_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "[*] Generating malicious MP4..."
python3 "$POC_DIR/vuln_001_gen.py"

echo "[*] Running mp42aac with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan.log:detect_odr_violation=0" \
  "$BINARY" "$POC_DIR/vuln_001.mp4" /dev/null \
  > "$POC_DIR/vuln_001_result.txt" 2>&1 || true

# Collect ASAN output from log files
echo "" >> "$POC_DIR/vuln_001_result.txt"
echo "=== ASAN log ===" >> "$POC_DIR/vuln_001_result.txt"
for f in "$POC_DIR"/asan.log.*; do
    if [ -f "$f" ]; then
        cat "$f" >> "$POC_DIR/vuln_001_result.txt"
    fi
done

echo "=== Run complete ===" >> "$POC_DIR/vuln_001_result.txt"

echo "[*] Done. Results in $POC_DIR/vuln_001_result.txt"
