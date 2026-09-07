#!/bin/bash
SCRIPT_DIR="/data/ylwang/non-textfuzz/target/_poc/jasper/src_appl_imginfo_c"
IMGINFO="/data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo"

echo "[*] Generating malicious JP2 file..."
python3 "$SCRIPT_DIR/vuln_001_gen.py"

echo "[*] Running imginfo on evil.jp2 (bypass sample limit with --max-samples 0)..."
ASAN_OPTIONS="abort_on_error=0:log_path=$SCRIPT_DIR/asan.log" \
UBSAN_OPTIONS="print_stacktrace=1:log_path=$SCRIPT_DIR/ubsan.log" \
  "$IMGINFO" \
  --max-samples 0 \
  -f "$SCRIPT_DIR/vuln_001.jp2" \
  > "$SCRIPT_DIR/vuln_001_result.txt" 2>&1 || true

echo "[*] Checking ASAN/UBSAN logs..."
for f in "$SCRIPT_DIR"/asan.log.* "$SCRIPT_DIR"/ubsan.log.*; do
  [ -f "$f" ] && grep -E "ERROR|UBSAN|runtime error|overflow|out.of.bounds|heap|signed integer" "$f" >> "$SCRIPT_DIR/vuln_001_result.txt" 2>/dev/null || true
done

echo "[*] Result:"
cat "$SCRIPT_DIR/vuln_001_result.txt"
echo ""
echo "[*] ASAN logs:"
ls "$SCRIPT_DIR"/asan.log.* 2>/dev/null && cat "$SCRIPT_DIR"/asan.log.* 2>/dev/null || echo "(no ASAN logs found)"
echo "[*] UBSAN logs:"
ls "$SCRIPT_DIR"/ubsan.log.* 2>/dev/null && cat "$SCRIPT_DIR"/ubsan.log.* 2>/dev/null || echo "(no UBSAN logs found)"
