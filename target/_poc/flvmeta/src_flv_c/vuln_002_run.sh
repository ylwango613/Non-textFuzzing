#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/flvmeta/src_flv_c"

BINARY="/data/ylwang/non-textfuzz/target/flvmeta/build_test/src/flvmeta"
FLV="vuln_002.flv"
RESULT="vuln_002_result.txt"

# Reset result file
: > "$RESULT"

# Step 1: generate FLV
python3 vuln_002_gen.py 2>&1 | tee -a "$RESULT"

echo "" >> "$RESULT"
echo "=== Normal run (malloc likely succeeds, but vulnerable path is reached) ===" >> "$RESULT"

# Step 2: normal run - should print "unknown metadata event name" warning
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002.log" \
  "$BINARY" --check "$FLV" >> "$RESULT" 2>&1 || true

echo "" >> "$RESULT"
echo "=== ulimit runs (attempt to trigger malloc failure) ===" >> "$RESULT"

# Step 3: memory-constrained runs to force malloc(name_len+50) to return NULL
# The binary + ASan overhead requires moderate memory; we sweep downward.
for MEM_LIMIT in 40000 30000 25000 20000 15000 12000; do
  echo "" >> "$RESULT"
  echo "--- ulimit -v $MEM_LIMIT KB ---" >> "$RESULT"
  (
    ulimit -v "$MEM_LIMIT" 2>/dev/null || true
    ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002_ulimit_${MEM_LIMIT}.log" \
      "$BINARY" --check "$FLV" 2>&1 || true
  ) >> "$RESULT" 2>&1 || true
done

echo "" >> "$RESULT"
echo "=== ASAN / UBSAN log excerpts ===" >> "$RESULT"

# Step 4: collect sanitizer output
for f in ./asan_002.log.* ./asan_002_ulimit_*.log.*; do
  [ -f "$f" ] || continue
  echo "--- $f ---" >> "$RESULT"
  grep -E "AddressSanitizer|ERROR:|runtime error:|SEGV|NULL|null pointer" "$f" >> "$RESULT" 2>/dev/null || true
done

echo "" >> "$RESULT"
echo "=== Done ===" >> "$RESULT"
cat "$RESULT"
