#!/bin/bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Command_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
RESULT="${POC_DIR}/vuln_003_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan.log"

# Generate all PoC files
python3 "${POC_DIR}/vuln_003_gen.py"

echo "==== VULN-003 Run Results ====" > "${RESULT}"
date >> "${RESULT}"

run_variant() {
    local label="$1"
    local mp4="$2"
    echo "" >> "${RESULT}"
    echo "--- Variant: ${label} (${mp4}) ---" >> "${RESULT}"

    ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}.${label}" \
    UBSAN_OPTIONS="print_stacktrace=1:abort_on_error=0" \
        "${BINARY}" "${mp4}" /dev/null \
        >> "${RESULT}" 2>&1 || true

    # Collect any ASAN/UBSAN log output
    for f in "${ASAN_LOG_PREFIX}.${label}".*; do
        [ -f "$f" ] || continue
        echo "  [ASAN/UBSAN log: $f]" >> "${RESULT}"
        grep -E "(ERROR|WARNING|runtime error|SUMMARY|AddressSanitizer|UndefinedBehavior|bad_alloc|terminate)" \
            "$f" >> "${RESULT}" 2>/dev/null || true
    done
}

# Primary variant
run_variant "p2_extra"  "${POC_DIR}/vuln_003_p2_extra.mp4"

# Fallback variants
run_variant "p2_plain"  "${POC_DIR}/vuln_003_p2_plain.mp4"
run_variant "p1_extra"  "${POC_DIR}/vuln_003_p1_extra.mp4"
run_variant "p0_extra"  "${POC_DIR}/vuln_003_p0_extra.mp4"

echo "" >> "${RESULT}"
echo "==== Done ====" >> "${RESULT}"
cat "${RESULT}"
