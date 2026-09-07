#!/bin/bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_luv_c"
TIFFSPLIT="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit"
RESULT="$POC_DIR/vuln_001_result.txt"

cd "$POC_DIR"

# Remove stale results
rm -f "$RESULT" asan.log.* vuln_001.tif

# Generate the malformed TIFF
python3 "$POC_DIR/vuln_001_gen.py"

echo "[*] Running tiffsplit on vuln_001.tif ..." | tee "$RESULT"

# Run under ASAN; allow it to finish even if it crashes
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log:detect_stack_use_after_return=1" \
  "$TIFFSPLIT" "$POC_DIR/vuln_001.tif" /tmp/tiffsplit_001_ >> "$RESULT" 2>&1 || true

# Collect any ASAN log output
for f in "$POC_DIR"/asan.log.*; do
    [ -f "$f" ] || continue
    echo "[ASAN LOG: $f]" >> "$RESULT"
    cat "$f" >> "$RESULT"
done

echo "[*] Result file: $RESULT"
cat "$RESULT"
