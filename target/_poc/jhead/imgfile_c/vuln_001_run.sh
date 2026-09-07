#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

JHEAD="/data/ylwang/non-textfuzz/target/jhead/build_test/jhead"
INPUT="vuln_001_input.jpg"
THUMB="vuln_001_thumb.jpg"
RESULT="vuln_001_result.txt"

# Generate the crafted JPEG if not already present
if [ ! -f "$INPUT" ]; then
    python3 vuln_001_gen.py
fi

# Clear previous results
rm -f "$RESULT" asan.log.*

# Run jhead with -st to trigger SaveImgThumbnail
ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan.log" \
    "$JHEAD" -st "$THUMB" "$INPUT" \
    > "$RESULT" 2>&1 || true

# Collect any ASan logs
for f in "${SCRIPT_DIR}"/asan.log.*; do
    if [ -f "$f" ]; then
        grep -E "AddressSanitizer|ERROR:|runtime error:|heap-buffer-overflow|SEGV" "$f" \
            >> "$RESULT" || true
    fi
done

echo ""
echo "=== vuln_001_result.txt ==="
cat "$RESULT"
