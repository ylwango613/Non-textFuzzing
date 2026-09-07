#!/bin/bash
POC_DIR=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IsfmAtom_h

# Step 1: Generate the crafted MP4
echo "[*] Generating crafted MP4..."
python3 "$POC_DIR/vuln_001_gen.py"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to generate MP4" >&2
    echo "ERROR" > "$POC_DIR/vuln_001_status.txt"
    exit 1
fi

# Step 2: Run mp42aac with ASAN
echo "[*] Running mp42aac with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
    /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
    --key 0123456789abcdef0123456789abcdef \
    "$POC_DIR/vuln_001.mp4" /dev/null \
    > "$POC_DIR/vuln_001_result.txt" 2>&1 || true

# Step 3: Collect ASAN output
if ls "$POC_DIR"/asan.log.* 1>/dev/null 2>&1; then
    cat "$POC_DIR"/asan.log.* >> "$POC_DIR/vuln_001_result.txt" 2>/dev/null || true
fi

# Step 4: Determine status
echo "[*] Result:"
cat "$POC_DIR/vuln_001_result.txt"

if grep -qE "stack-buffer-overflow|heap-buffer-overflow|out-of-bounds|AddressSanitizer|ASAN|UBSan|runtime error" \
        "$POC_DIR/vuln_001_result.txt" 2>/dev/null; then
    echo "VERIFIED_CRASH" > "$POC_DIR/vuln_001_status.txt"
    echo "[+] STATUS: VERIFIED_CRASH"
else
    echo "UNVERIFIED" > "$POC_DIR/vuln_001_status.txt"
    echo "[-] STATUS: UNVERIFIED (no sanitizer output detected)"
fi
