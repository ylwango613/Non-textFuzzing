#!/bin/bash
# PoC runner for VULN-001: OOB Read in rv40_strong_loop_filter
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted RealMedia file..."
python3 vuln_001_gen.py

echo "[*] Running FFmpeg with ASAN on vuln_001_input.rm..."
# Use -threads 1 to avoid frame-threading code paths that skip the loop filter.
# Use -flags +bitexact to avoid non-deterministic output.
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:detect_stack_use_after_return=1:check_initialization_order=1" \
  "$BIN" -threads 1 -i vuln_001_input.rm -f null - > vuln_001_result.txt 2>&1 || true

echo "[*] Collecting ASAN log..."
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "[*] Done. Results in vuln_001_result.txt"
