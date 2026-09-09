#!/usr/bin/env bash
# VULN 002 run script — TrueMotion1 24-bit missing keyframe guard
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
GEN_PY="$SCRIPT_DIR/vuln_002_gen.py"
INPUT="$SCRIPT_DIR/vuln_002_input.avi"

echo "=== VULN 002: truemotion1_decode_24bit() missing keyframe guard ==="
echo "=== File: libavcodec/truemotion1.c line 783 ==="
echo ""

# Step 1: Generate the crafted AVI
echo "[1] Generating crafted AVI..."
python3 "$GEN_PY"
echo ""

# Step 2: Run ffmpeg with the crafted input
echo "[2] Running ffmpeg (ASAN-enabled build)..."
echo "    Binary: $FFMPEG"
echo "    Input:  $INPUT"
echo ""

# Disable ASAN abort so we capture all output; re-enable crash exit code
export ASAN_OPTIONS="abort_on_error=0:exitcode=42:print_stacktrace=1:detect_leaks=0"

set +e
"$FFMPEG" -v debug -i "$INPUT" -f null - 2>&1
EXIT_CODE=$?
set -e

echo ""
echo "[3] ffmpeg exit code: $EXIT_CODE"

if [ $EXIT_CODE -eq 42 ]; then
    echo "[!] ASAN CRASH DETECTED (exit code 42)"
elif [ $EXIT_CODE -ne 0 ]; then
    echo "[!] Non-zero exit code: $EXIT_CODE (may indicate error or ASAN signal)"
else
    echo "[*] ffmpeg exited cleanly (exit code 0)"
fi
