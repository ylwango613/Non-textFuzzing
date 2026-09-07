#!/bin/bash
# vuln_003_run.sh - Run PoC for VULN-003
# Integer Underflow in AP4_RtpSampleData Constructor (Ap4RtpHint.cpp:70)

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4HintTrackReader_cpp"
MP42AAC="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${POC_DIR}/vuln_003.mp4"
RESULT="${POC_DIR}/vuln_003_result.txt"
ASAN_LOG="${POC_DIR}/asan_003.log"

cd "${POC_DIR}"

# Generate the PoC file
python3 vuln_003_gen.py

echo "=== mp42aac run ===" > "${RESULT}"
echo "Input: ${INPUT}" >> "${RESULT}"
echo "Tool:  ${MP42AAC}" >> "${RESULT}"
echo "" >> "${RESULT}"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "${MP42AAC}" \
  "${INPUT}" \
  /dev/null \
  >> "${RESULT}" 2>&1 || true

# Append any ASAN log files
for f in "${ASAN_LOG}".*; do
  [ -f "$f" ] && cat "$f" >> "${RESULT}"
done

echo "" >> "${RESULT}"
echo "=== exit code collected ===" >> "${RESULT}"
