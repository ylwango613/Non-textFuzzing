#!/bin/bash
# PoC runner for VULN-001: Heap OOB Read in ccaption_dec.c decode()
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
RESULT=vuln_001_result.txt

echo "=== VULN-001 PoC Run ===" | tee "$RESULT"
echo "Date: $(date)" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Step 1: Generate the crafted MP4
echo "[*] Generating crafted MP4 with 2-byte c608 subtitle sample..." | tee -a "$RESULT"
python3 vuln_001_gen.py 2>&1 | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

INPUT="$SCRIPT_DIR/vuln_001_input.mp4"
if [ ! -f "$INPUT" ]; then
    echo "[ERROR] Input file not generated" | tee -a "$RESULT"
    exit 1
fi

# Step 2: Run ffmpeg with ASAN
echo "[*] Running ffmpeg (attempt 1: -map 0 -f null)..." | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan.log:detect_leaks=0" \
    "$BIN" -y -i "$INPUT" -map 0 -f null - >> "$RESULT" 2>&1 || true

# Collect ASAN output
if ls "${SCRIPT_DIR}"/asan.log.* 2>/dev/null | grep -q .; then
    echo "" | tee -a "$RESULT"
    echo "[*] ASAN log:" | tee -a "$RESULT"
    cat "${SCRIPT_DIR}"/asan.log.* >> "$RESULT" 2>/dev/null || true
    rm -f "${SCRIPT_DIR}"/asan.log.*
fi

echo "" | tee -a "$RESULT"
echo "[*] Running ffmpeg (attempt 2: -map 0:s to .srt output)..." | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan2.log:detect_leaks=0" \
    "$BIN" -y -i "$INPUT" -map 0:s "${SCRIPT_DIR}/vuln_001_out.srt" >> "$RESULT" 2>&1 || true

if ls "${SCRIPT_DIR}"/asan2.log.* 2>/dev/null | grep -q .; then
    echo "" | tee -a "$RESULT"
    echo "[*] ASAN log (attempt 2):" | tee -a "$RESULT"
    cat "${SCRIPT_DIR}"/asan2.log.* >> "$RESULT" 2>/dev/null || true
    rm -f "${SCRIPT_DIR}"/asan2.log.*
fi

echo "" | tee -a "$RESULT"
echo "[*] Running ffmpeg (attempt 3: -map 0:s to .ass output)..." | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan3.log:detect_leaks=0" \
    "$BIN" -y -i "$INPUT" -map 0:s "${SCRIPT_DIR}/vuln_001_out.ass" >> "$RESULT" 2>&1 || true

if ls "${SCRIPT_DIR}"/asan3.log.* 2>/dev/null | grep -q .; then
    echo "" | tee -a "$RESULT"
    echo "[*] ASAN log (attempt 3):" | tee -a "$RESULT"
    cat "${SCRIPT_DIR}"/asan3.log.* >> "$RESULT" 2>/dev/null || true
    rm -f "${SCRIPT_DIR}"/asan3.log.*
fi

echo "" | tee -a "$RESULT"
echo "[*] Running ffmpeg (attempt 4: -f ass pipe output)..." | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan4.log:detect_leaks=0" \
    "$BIN" -y -i "$INPUT" -map 0:s -f ass - >> "$RESULT" 2>&1 || true

if ls "${SCRIPT_DIR}"/asan4.log.* 2>/dev/null | grep -q .; then
    echo "" | tee -a "$RESULT"
    echo "[*] ASAN log (attempt 4):" | tee -a "$RESULT"
    cat "${SCRIPT_DIR}"/asan4.log.* >> "$RESULT" 2>/dev/null || true
    rm -f "${SCRIPT_DIR}"/asan4.log.*
fi

echo "" | tee -a "$RESULT"
echo "[*] Running ffprobe with -show_packets (attempt 5)..." | tee -a "$RESULT"
FFPROBE=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffprobe
if [ -f "$FFPROBE" ]; then
    ASAN_OPTIONS="abort_on_error=0:log_path=${SCRIPT_DIR}/asan5.log:detect_leaks=0" \
        "$FFPROBE" -i "$INPUT" -show_packets -read_intervals "%+#10" >> "$RESULT" 2>&1 || true
    if ls "${SCRIPT_DIR}"/asan5.log.* 2>/dev/null | grep -q .; then
        echo "" | tee -a "$RESULT"
        echo "[*] ASAN log (attempt 5 ffprobe):" | tee -a "$RESULT"
        cat "${SCRIPT_DIR}"/asan5.log.* >> "$RESULT" 2>/dev/null || true
        rm -f "${SCRIPT_DIR}"/asan5.log.*
    fi
fi

echo "" | tee -a "$RESULT"
echo "=== Done ===" | tee -a "$RESULT"
