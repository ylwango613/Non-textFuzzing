#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

# Step 1: Check if ARIB decoder is compiled in
if ! "$BIN" -decoders 2>/dev/null | grep -qi arib; then
    echo "SKIPPED: arib decoder not compiled"
    exit 0
fi

# Step 2: Generate crafted input
python3 vuln_001_gen.py

# Step 3: Run ffmpeg with -sub_type bitmap to trigger clut_init() path
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -i vuln_001_input.ts -sub_type bitmap -f null - > vuln_001_result.txt 2>&1 || true

# Collect ASAN output if present
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "Done. Check vuln_001_result.txt for results."
