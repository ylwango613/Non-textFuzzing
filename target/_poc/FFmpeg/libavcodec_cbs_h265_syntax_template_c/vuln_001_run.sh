#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
python3 vuln_001_gen.py
# ASAN_OPTIONS: log ASAN reports to asan.log.*
# UBSAN_OPTIONS: log UBSan (UndefinedBehaviorSanitizer) reports to stderr (default)
# -c:v copy: bypass decoding so packets reach the trace_headers BSF directly
# -bsf:v trace_headers: invoke CBS to parse each NAL unit (triggers OOB in sei_pic_timing)
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  "$BIN" -i vuln_001_input.h265 -c:v copy -bsf:v trace_headers -f null - > vuln_001_result.txt 2>&1 || true
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true
