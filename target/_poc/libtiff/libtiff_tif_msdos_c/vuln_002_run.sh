#!/bin/bash
set -euo pipefail
POCDIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_msdos_c"
TIFFSPLIT="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit"
cd "$POCDIR"

# Generate all variant TIFFs
python3 vuln_002_gen.py

RESULT="$POCDIR/vuln_002_result.txt"
> "$RESULT"

run_variant() {
    local tif="$1"
    local label="$2"
    echo "=== $label ===" >> "$RESULT"
    ASAN_OPTIONS="abort_on_error=0:log_path=${POCDIR}/asan_${label}.log" \
      "$TIFFSPLIT" "$tif" /tmp/tiffsplit_out_${label}_ >> "$RESULT" 2>&1 || true
    # Collect any ASAN/UBSAN log output
    for f in "${POCDIR}/asan_${label}.log".*; do
        [ -f "$f" ] && {
            echo "--- ASAN/UBSAN output for $label ---" >> "$RESULT"
            cat "$f" >> "$RESULT"
        } || true
    done
    echo "" >> "$RESULT"
}

run_variant "vuln_002.tif"       "v1_UINT_MAX"
run_variant "vuln_002_zero.tif"  "v2_ZERO"
run_variant "vuln_002_intmin.tif" "v3_INT32_MIN"
run_variant "vuln_002_over.tif"  "v4_OVER_INT32_MAX"

echo "=== DONE ===" >> "$RESULT"
cat "$RESULT"
