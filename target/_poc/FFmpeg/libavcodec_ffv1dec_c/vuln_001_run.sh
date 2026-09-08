#!/bin/bash
# vuln_001_run.sh — Run the FFV1 OOB PoC (VULN-001)
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "=== FFV1 VULN-001 PoC ==="
echo "Binary: $BIN"
echo ""

# Generate the crafted input files
echo "[*] Generating crafted FFV1 files..."
python3 vuln_001_gen.py
echo ""

# Run through ASAN-instrumented ffmpeg
ASAN_OPTS="abort_on_error=0:log_path=./asan_log"

for INPUT in vuln_001_input.avi vuln_001_input2.avi; do
    if [ ! -f "$INPUT" ]; then
        echo "[!] $INPUT not found, skipping"
        continue
    fi

    echo "--- Testing $INPUT ---"
    ASAN_OPTIONS="$ASAN_OPTS" \
        "$BIN" -hide_banner -loglevel warning \
               -i "$INPUT" -f null - 2>&1 || true
    echo ""
done

# Collect ASAN logs
if ls asan_log.* 1>/dev/null 2>&1; then
    echo "=== ASAN LOG ==="
    cat asan_log.* 2>/dev/null || true
fi
