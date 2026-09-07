#!/bin/bash
# vuln_001_run.sh - Attempt to trigger OOB read in gdip_bitmap_get_frame_delay()
# NOTE: This will be SKIPPED on Linux because io-gdip is a Windows-only loader.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_PY="$SCRIPT_DIR/vuln_001_gen.py"
INPUT="$SCRIPT_DIR/vuln_001.gif"
OUTPUT="$SCRIPT_DIR/vuln_001_out.c"
RESULT="$SCRIPT_DIR/vuln_001_result.txt"
ASAN_LOG="$SCRIPT_DIR/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"

python3 "$GEN_PY" "$INPUT"

ASAN_OPTIONS="abort_on_error=0:log_path=$ASAN_LOG" \
  "$BINARY" "$INPUT" "$OUTPUT" > "$RESULT" 2>&1 || true

echo "Exit code: $?" >> "$RESULT"
