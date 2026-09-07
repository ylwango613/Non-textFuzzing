#!/bin/bash
set -e

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4EsdsAtom_cpp"
MP42AAC="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_001.mp4"
RESULT="$POC_DIR/vuln_001_result.txt"

echo "[*] Generating malformed MP4..."
python3 "$POC_DIR/vuln_001_gen.py"

echo "[*] Running mp42aac on malformed input..."
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log:print_stacktrace=1" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=$POC_DIR/ubsan.log" \
  "$MP42AAC" "$INPUT" /dev/null \
  > "$RESULT" 2>&1 || true

# Collect any ASAN/UBSAN log files
for f in "$POC_DIR"/asan.log.* "$POC_DIR"/ubsan.log.*; do
    if [ -f "$f" ]; then
        echo "" >> "$RESULT"
        echo "=== from $f ===" >> "$RESULT"
        cat "$f" >> "$RESULT"
    fi
done

echo "[*] Run complete. Result in $RESULT"
echo ""
echo "=== OUTPUT ==="
cat "$RESULT"
