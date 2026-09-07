#!/bin/bash
# Run script for VULN 002: Integer Underflow in AP4_EsDescriptor
# Target: Bento4 mp42aac

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4EsdsAtom_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_002.mp4"
OUTPUT="/dev/null"
RESULT="$POC_DIR/vuln_002_result.txt"
ASAN_LOG="$POC_DIR/asan.log"

# ---- Step 1: Generate the PoC MP4 ----------------------------------------
echo "[*] Generating vuln_002.mp4 ..."
python3 "$POC_DIR/vuln_002_gen.py"

# ---- Step 2: Run the binary -----------------------------------------------
echo "[*] Running mp42aac ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "$BINARY" "$INPUT" "$OUTPUT" \
  > "$RESULT" 2>&1 || true

# ---- Step 3: Collect any ASAN reports -------------------------------------
for f in "${ASAN_LOG}".*; do
    [ -f "$f" ] && {
        echo "--- ASAN report: $f ---" >> "$RESULT"
        cat "$f" >> "$RESULT"
    }
done

echo "[*] Done. Results in: $RESULT"
