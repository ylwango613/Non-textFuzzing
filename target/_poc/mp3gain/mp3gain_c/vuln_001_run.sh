#!/usr/bin/env bash
# VULN 001 run script: mp3gain apetag.c heap-buffer-over-read (MP3GAIN_UNDO vsize=0)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MP3FILE="$SCRIPT_DIR/vuln_001.mp3"
RESULT="$SCRIPT_DIR/vuln_001_result.txt"
BINARY="/data/ylwang/non-textfuzz/target/mp3gain/build_test/mp3gain"

# Step 1: Generate the crafted MP3 if it doesn't exist
if [ ! -f "$MP3FILE" ]; then
    echo "[*] Generating vuln_001.mp3 ..."
    python3 "$SCRIPT_DIR/vuln_001_gen.py"
fi

echo "[*] Running mp3gain against crafted file..."

# Step 2: Run mp3gain with ASAN options; capture stdout+stderr
{
    ASAN_OPTIONS="halt_on_error=0:detect_leaks=0" \
    UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
    "$BINARY" -q "$MP3FILE" 2>&1 || true
} > "$RESULT" 2>&1

echo "[*] Run complete. Checking for ASAN/UBSAN errors..."

# Step 3: Grep ASAN/UBSAN markers and append summary
RESULT_SNAP=$(cat "$RESULT")
{
    echo ""
    echo "=== ASAN/UBSAN error scan ==="
    if echo "$RESULT_SNAP" | grep -qE "(ERROR: AddressSanitizer|heap-buffer-overflow|heap-buffer-over-read|READ of size|WRITE of size|runtime error:|stack-buffer-overflow|use-after-free|undefined behaviour)"; then
        echo "STATUS: ASAN/UBSAN errors detected"
        echo "$RESULT_SNAP" | grep -E "(ERROR: AddressSanitizer|heap-buffer-overflow|heap-buffer-over-read|READ of size|WRITE of size|runtime error:|stack-buffer-overflow|use-after-free|undefined behaviour|SUMMARY)"
    else
        echo "STATUS: No ASAN/UBSAN errors detected in output"
    fi
} >> "$RESULT"

echo "[*] Results written to $RESULT"
cat "$RESULT"
