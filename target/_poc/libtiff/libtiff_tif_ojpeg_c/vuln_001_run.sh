#!/bin/bash
# Run tiffsplit against the OJPEG vuln_001.tif PoC and capture ASAN output.
# Vulnerability: OJPEGWriteHeaderInfo() integer overflow (libtiff tif_ojpeg.c:1142)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIFF="$SCRIPT_DIR/vuln_001.tif"
TIFFSPLIT="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit"
ASAN_LOG_BASE="$SCRIPT_DIR/asan_vuln_001"

# Step 1: generate the TIFF file
echo "[*] Generating vuln_001.tif ..."
python3 "$SCRIPT_DIR/vuln_001_gen.py"
echo ""

# Step 2: verify the binary exists
if [ ! -x "$TIFFSPLIT" ]; then
    echo "[ERROR] tiffsplit not found: $TIFFSPLIT"
    exit 1
fi

# Step 3: run tiffsplit with ASAN logging
echo "[*] Running: $TIFFSPLIT $TIFF"
echo "[*] ASAN log base: ${ASAN_LOG_BASE}.<pid>"
echo ""

export ASAN_OPTIONS="log_path=${ASAN_LOG_BASE}:halt_on_error=0:detect_leaks=0:print_summary=1"
export LSAN_OPTIONS="detect_leaks=0"

"$TIFFSPLIT" "$TIFF" "$SCRIPT_DIR/vuln_001_out_" 2>&1
EXIT_CODE=$?
echo ""
echo "[*] tiffsplit exit code: $EXIT_CODE"
echo ""

# Step 4: collect ASAN output
ASAN_FILES=("${ASAN_LOG_BASE}".* 2>/dev/null || true)
FOUND_ASAN=0
for f in "${ASAN_LOG_BASE}".*; do
    if [ -f "$f" ]; then
        FOUND_ASAN=1
        echo "[*] ASAN log: $f"
        cat "$f"
        echo ""
    fi
done

if [ "$FOUND_ASAN" -eq 0 ]; then
    echo "[*] No ASAN log files generated (expected — tiffsplit cannot reach OJPEGPreDecode)."
fi

# Step 5: clean up any output TIFF files produced
rm -f "$SCRIPT_DIR/vuln_001_out_"*.tif 2>/dev/null || true

echo "[*] Done."
