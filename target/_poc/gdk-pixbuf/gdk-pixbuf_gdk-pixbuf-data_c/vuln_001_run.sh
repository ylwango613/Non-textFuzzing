#!/bin/bash
# Run script for VULN-001: Integer overflow in gdk_pixbuf_new_from_bytes
# Note: Status is expected to be SKIPPED because gdk_pixbuf_new_from_bytes
# is not reachable from gdk-pixbuf-pixdata.

POC_DIR=/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-data_c
BINARY=/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata

python3 $POC_DIR/vuln_001_gen.py

ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  $BINARY $POC_DIR/vuln_001.bmp $POC_DIR/vuln_001_out.c \
  > $POC_DIR/vuln_001_result.txt 2>&1 || true
