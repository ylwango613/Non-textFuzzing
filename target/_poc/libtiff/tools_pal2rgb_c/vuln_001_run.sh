#!/usr/bin/env bash
# PoC runner for libtiff pal2rgb VULN 001
# Heap buffer overflow via TIFFScanlineSize integer overflow -> malloc(0) obuf

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PAL2RGB="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/pal2rgb"
INPUT_TIF="$SCRIPT_DIR/vuln_001.tif"
OUTPUT_TIF="/tmp/pal2rgb_out_001.tif"
RESULT="$SCRIPT_DIR/vuln_001_result.txt"
ASAN_LOG="$SCRIPT_DIR/asan.log"

echo "[*] VULN 001 - pal2rgb heap buffer overflow via malloc(0) obuf" | tee "$RESULT"
echo "[*] Date: $(date)" | tee -a "$RESULT"

# Step 1: Generate the TIFF if it doesn't exist
if [ ! -f "$INPUT_TIF" ]; then
    echo "[*] Generating vuln_001.tif ..." | tee -a "$RESULT"
    python3 "$SCRIPT_DIR/vuln_001_gen.py" 2>&1 | tee -a "$RESULT"
else
    echo "[*] vuln_001.tif already exists ($(wc -c < "$INPUT_TIF") bytes)" | tee -a "$RESULT"
fi

# Step 2: Run pal2rgb under ASAN
echo "[*] Running pal2rgb ..." | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
    "$PAL2RGB" "$INPUT_TIF" "$OUTPUT_TIF" \
    >> "$RESULT" 2>&1 || true

echo "[*] pal2rgb exited" | tee -a "$RESULT"

# Step 3: Collect ASAN output
echo "" >> "$RESULT"
echo "[*] === ASAN log ===" | tee -a "$RESULT"
for f in "${ASAN_LOG}".*; do
    if [ -f "$f" ]; then
        echo "--- $f ---" >> "$RESULT"
        cat "$f" >> "$RESULT"
    fi
done

# Also check if ASAN wrote to stderr (captured above) or a plain log file
if [ -f "${ASAN_LOG}" ]; then
    echo "--- ${ASAN_LOG} ---" >> "$RESULT"
    cat "${ASAN_LOG}" >> "$RESULT"
fi

# Step 4: Summarize
echo "" | tee -a "$RESULT"
echo "[*] === Summary ===" | tee -a "$RESULT"
if grep -q "heap-buffer-overflow\|AddressSanitizer\|SEGV\|heap overflow" "$RESULT" 2>/dev/null; then
    echo "[!] CRASH DETECTED - ASAN triggered" | tee -a "$RESULT"
else
    echo "[-] No ASAN crash signature found in output" | tee -a "$RESULT"
fi

echo "[*] Done. See $RESULT for full output." | tee -a "$RESULT"
