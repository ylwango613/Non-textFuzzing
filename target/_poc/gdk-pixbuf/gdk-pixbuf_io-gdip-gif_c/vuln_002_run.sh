#!/bin/bash
# VULN 002 PoC Runner
# NULL Pointer Dereference via Unchecked g_try_malloc in GDI+ Property Functions

cd /data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-gif_c/

echo "[*] Generating PoC GIF files..."
python3 vuln_002_gen.py

echo ""
echo "[*] Running gdk-pixbuf-pixdata against vuln_002.gif ..."
ASAN_OPTIONS="abort_on_error=0:log_path=/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-gif_c/asan.log" \
  /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata \
  vuln_002.gif \
  vuln_002_out.c \
  > vuln_002_result.txt 2>&1 || true
echo "Exit code: $?"
cat vuln_002_result.txt

echo ""
echo "[*] Checking for ASAN output..."
ls asan.log* 2>/dev/null && cat asan.log* || echo "(no ASAN log files)"

echo ""
echo "[*] Checking available GDI+ loaders..."
cat /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache
