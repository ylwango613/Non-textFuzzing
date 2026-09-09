#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
INPUT="$SCRIPT_DIR/vuln_001_input.avi"

echo "[*] Generating crafted AVI..."
python3 "$SCRIPT_DIR/vuln_001_gen.py"

echo ""
echo "[*] Running ffmpeg on crafted input..."
echo "    $FFMPEG -i $INPUT -f null -"
echo ""

"$FFMPEG" -i "$INPUT" -f null - 2>&1
EXIT_CODE=$?

echo ""
echo "[*] ffmpeg exit code: $EXIT_CODE"
exit $EXIT_CODE
