#!/bin/bash
# Run script for VULN 001 — AP4_CttsAtom Integer Overflow -> Heap OOB Read
# Target: Bento4 mp42aac (ASAN+UBSAN build)

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomSampleTable_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

# Generate the malicious MP4
python3 "$POC_DIR/vuln_001_gen.py"

# Run under ASAN/UBSAN — capture all output
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  "$BINARY" \
  "$POC_DIR/vuln_001.mp4" /dev/null \
  > "$POC_DIR/vuln_001_result.txt" 2>&1 || true

# Append any separate ASAN log files produced by the sanitizers
for f in "$POC_DIR"/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> "$POC_DIR/vuln_001_result.txt"
done

echo "[*] Run complete. Results in $POC_DIR/vuln_001_result.txt"
