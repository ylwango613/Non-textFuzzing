#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Dec3Atom_cpp"
MP42AAC="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_001.mp4"
RESULT="$POC_DIR/vuln_001_result.txt"
ASAN_LOG_BASE="$POC_DIR/asan.log"

echo "[*] Generating vuln_001.mp4 ..."
python3 "$POC_DIR/vuln_001_gen.py"

echo "[*] Running mp42aac ..." > "$RESULT"
echo "    Binary: $MP42AAC"    >> "$RESULT"
echo "    Input:  $INPUT"      >> "$RESULT"
echo "" >> "$RESULT"

# Remove any old asan logs for this run
rm -f "$ASAN_LOG_BASE".*

# Run mp42aac under ASAN; capture both stdout/stderr
set +e
ASAN_OPTIONS="detect_leaks=0:log_path=${ASAN_LOG_BASE}:exitcode=42" \
    "$MP42AAC" "$INPUT" /dev/null 2>&1 | tee -a "$RESULT"
EXIT_CODE=$?
set -e

echo "" >> "$RESULT"
echo "=== Exit code: $EXIT_CODE ===" >> "$RESULT"

echo "" >> "$RESULT"
echo "=== ASAN / UBSAN log ===" >> "$RESULT"
ASAN_FILES=("$ASAN_LOG_BASE".*)
if compgen -G "$ASAN_LOG_BASE.*" > /dev/null 2>&1; then
    cat "$ASAN_LOG_BASE".* >> "$RESULT"
    grep -h "ERROR\|SUMMARY\|AddressSanitizer\|heap-buffer-overflow\|READ\|WRITE\|UndefinedBehavior" \
         "$ASAN_LOG_BASE".* 2>/dev/null \
        | head -40 >> "$RESULT" || true
else
    echo "(no asan log files found)" >> "$RESULT"
fi

echo "" >> "$RESULT"
echo "=== Key grep results ===" >> "$RESULT"
grep -h -i "overflow\|oob\|out.of.bounds\|read\|summary\|error\|crash\|ubsan\|undefined" \
     "$ASAN_LOG_BASE".* 2>/dev/null | head -20 >> "$RESULT" || echo "(no matches)" >> "$RESULT"

cat "$RESULT"
