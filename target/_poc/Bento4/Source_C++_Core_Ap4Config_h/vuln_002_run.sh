#!/usr/bin/env bash
# vuln_002_run.sh — PoC runner for VULN-002 (AP4_Stz2Atom integer overflow)

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Config_h"
MP4="${POC_DIR}/vuln_002.mp4"
RESULT="${POC_DIR}/vuln_002_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan_002.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

# --- Step 1: Generate the malicious MP4 ---
echo "[*] Generating vuln_002.mp4 ..."
python3 "${POC_DIR}/vuln_002_gen.py"
if [ $? -ne 0 ]; then
    echo "[!] gen.py failed" | tee "${RESULT}"
    exit 1
fi

# --- Step 2: Run mp42aac under ASAN ---
echo "[*] Running mp42aac ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
    "${BINARY}" "${MP4}" /dev/null \
    > "${RESULT}" 2>&1 || true

# --- Step 3: Collect ASAN/UBSAN output ---
echo "" >> "${RESULT}"
echo "=== ASAN/UBSAN log output ===" >> "${RESULT}"
for log in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "${log}" ]; then
        echo "--- ${log} ---" >> "${RESULT}"
        cat "${log}" >> "${RESULT}"
    fi
done

# Also grep for key patterns inline
for log in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "${log}" ]; then
        grep -Ea "(ERROR:|WARNING:|SUMMARY:|heap-buffer-overflow|heap-use-after-free|use-after-free|stack-buffer|SEGV|runtime error|integer overflow|abort)" \
            "${log}" >> "${RESULT}" 2>/dev/null || true
    fi
done

echo "[*] Done. Results: ${RESULT}"
