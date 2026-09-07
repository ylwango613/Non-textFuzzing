#!/bin/bash
cd /data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-gif_c/
python3 vuln_001_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-gif_c/asan.log" \
  /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata \
  vuln_001.gif \
  vuln_001_out.c \
  > vuln_001_result.txt 2>&1 || true
echo "Exit code: $?"
cat vuln_001_result.txt
