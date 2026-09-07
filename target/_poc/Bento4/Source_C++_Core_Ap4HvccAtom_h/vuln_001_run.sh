#!/bin/bash
set -e
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4HvccAtom_h"
MP4_FILE="$POC_DIR/vuln_001.mp4"
RESULT_FILE="$POC_DIR/vuln_001_result.txt"
ASAN_LOG_PREFIX="$POC_DIR/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

# 1. 生成恶意 MP4
python3 "$POC_DIR/vuln_001_gen.py"

# 2. 运行 mp42aac（ASAN/UBSAN 检测）
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
  "$BINARY" "$MP4_FILE" /dev/null \
  > "$RESULT_FILE" 2>&1 || true

# 3. 收集 ASAN/UBSAN 报告
for f in "$POC_DIR"/asan.log.*; do
    [ -f "$f" ] && cat "$f" >> "$RESULT_FILE"
done
echo "[run.sh] Done. Check $RESULT_FILE"
