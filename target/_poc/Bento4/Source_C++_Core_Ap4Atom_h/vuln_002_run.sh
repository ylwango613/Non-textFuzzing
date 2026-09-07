#!/bin/bash
# PoC runner for Bento4 VULN 002:
# AP4_CttsAtom Integer Overflow -> Heap OOB Read

POC_DIR=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Atom_h
BINARY=/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac

echo "=== Bento4 VULN 002 PoC ===" | tee "$POC_DIR/vuln_002_result.txt"
echo "Generating malicious MP4..." | tee -a "$POC_DIR/vuln_002_result.txt"

python3 "$POC_DIR/vuln_002_gen.py" 2>&1 | tee -a "$POC_DIR/vuln_002_result.txt"

echo "Running mp42aac with malicious MP4..." | tee -a "$POC_DIR/vuln_002_result.txt"

ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  "$BINARY" \
  "$POC_DIR/vuln_002.mp4" /dev/null \
  >> "$POC_DIR/vuln_002_result.txt" 2>&1 || true

echo "Exit code: $?" >> "$POC_DIR/vuln_002_result.txt"

# Collect any ASAN log files
for f in "$POC_DIR"/asan.log.*; do
  if [ -f "$f" ]; then
    echo "=== ASAN log: $f ===" >> "$POC_DIR/vuln_002_result.txt"
    cat "$f" >> "$POC_DIR/vuln_002_result.txt"
  fi
done

echo "=== Done ===" >> "$POC_DIR/vuln_002_result.txt"
echo "Results written to $POC_DIR/vuln_002_result.txt"
