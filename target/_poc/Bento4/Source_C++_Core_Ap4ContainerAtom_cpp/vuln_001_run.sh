#!/bin/bash
# PoC runner for VULN 001: Integer Underflow in ReadChildren
# via Crafted 64-bit Full/Non-full Container Atom Size
set -euo pipefail

OUT_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ContainerAtom_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
RESULT="$OUT_DIR/vuln_001_result.txt"

# ── sanity checks ─────────────────────────────────────────────────────────
if [ ! -f "$BINARY" ]; then
    echo "ERROR: binary not found: $BINARY" | tee "$RESULT"
    exit 1
fi

# ── generate PoC files ────────────────────────────────────────────────────
echo "[*] Generating PoC files..."
python3 "$OUT_DIR/vuln_001_gen.py"

# ── run all variants ──────────────────────────────────────────────────────
: > "$RESULT"
printf '=== VULN 001 PoC Run Results ===\n' >> "$RESULT"
printf 'Date: %s\n\n' "$(date)" >> "$RESULT"

CRASH_FOUND=0

for poc in "$OUT_DIR"/vuln_001*.mp4; do
    variant="$(basename "$poc")"
    echo "--- Variant: $variant ---" >> "$RESULT"

    # Run with ASAN/UBSAN options
    ASAN_OPTIONS="abort_on_error=0:log_path=$OUT_DIR/asan_${variant%.mp4}" \
    UBSAN_OPTIONS="abort_on_error=0:log_path=$OUT_DIR/ubsan_${variant%.mp4}" \
    timeout 10 "$BINARY" "$poc" /dev/null \
        >> "$RESULT" 2>&1 || {
        EC=$?
        printf 'Exit code: %d\n' "$EC" >> "$RESULT"
        if [ "$EC" -ne 0 ]; then
            CRASH_FOUND=1
        fi
    }

    # Collect ASAN log files
    for logf in "$OUT_DIR"/asan_${variant%.mp4}.*; do
        if [ -f "$logf" ]; then
            printf '\n[ASAN log: %s]\n' "$logf" >> "$RESULT"
            cat "$logf" >> "$RESULT"
            CRASH_FOUND=1
        fi
    done

    # Collect UBSAN log files
    for logf in "$OUT_DIR"/ubsan_${variant%.mp4}.*; do
        if [ -f "$logf" ]; then
            printf '\n[UBSAN log: %s]\n' "$logf" >> "$RESULT"
            cat "$logf" >> "$RESULT"
            CRASH_FOUND=1
        fi
    done

    printf '\n' >> "$RESULT"
done

printf '=== Done ===\n' >> "$RESULT"

# ── summary ───────────────────────────────────────────────────────────────
echo "[*] Results written to: $RESULT"
if [ "$CRASH_FOUND" -eq 1 ]; then
    echo "[!] CRASH/SANITIZER ERROR DETECTED"
else
    echo "[*] No crash/sanitizer error detected"
fi
