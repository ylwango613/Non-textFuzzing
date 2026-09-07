#!/bin/bash
# VULN 001 PoC Runner: Integer Overflow in EnsureCapacity via Crafted elst entry_count
# Bento4 mp42aac - Ap4ElstAtom.cpp:72-73 + Ap4Array.h:172

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_001.mp4"
OUTPUT_TXT="$POC_DIR/vuln_001_result.txt"
ASAN_LOG="$POC_DIR/asan.log"

# Step 1: Generate the crafted MP4
echo "[*] Generating vuln_001.mp4 ..."
python3 /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_cpp/vuln_001_gen.py

# Step 2: Run mp42aac with ASAN logging
echo "[*] Running mp42aac ..."
ASAN_OPTIONS="abort_on_error=0:log_path=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_cpp/asan.log:hard_rss_limit_mb=1024" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_cpp/vuln_001.mp4 \
  /dev/null \
  > /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_cpp/vuln_001_result.txt 2>&1 || true

# Step 3: Grep ASAN/UBSAN error lines from asan.log.* and append to result
echo "" >> "$OUTPUT_TXT"
echo "=== ASAN/UBSAN Log Output ===" >> "$OUTPUT_TXT"
for logfile in "${ASAN_LOG}".*; do
    if [ -f "$logfile" ]; then
        echo "--- $logfile ---" >> "$OUTPUT_TXT"
        grep -E "ERROR:|SUMMARY:|runtime error:|AddressSanitizer|UndefinedBehavior|terminate|bad_alloc|SEGV|heap-buffer|stack-buffer|use-after|double-free|overflow" "$logfile" >> "$OUTPUT_TXT" 2>/dev/null || cat "$logfile" >> "$OUTPUT_TXT"
    fi
done

# Also check for log without PID suffix
if [ -f "$ASAN_LOG" ]; then
    echo "--- $ASAN_LOG ---" >> "$OUTPUT_TXT"
    cat "$ASAN_LOG" >> "$OUTPUT_TXT"
fi

echo "[*] Done. Results in $OUTPUT_TXT"
cat "$OUTPUT_TXT"
