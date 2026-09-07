#!/bin/bash
# VULN 001 - Heap OOB Read in gdip_bitmap_get_frame_delay
# STATUS: SKIPPED - GDI+ loader not available on Linux
#
# This script is a stub. The io-gdip-ico.c / io-gdip-utils.c loaders
# require the Windows GDI+ API and are not compiled into this Linux build.
#
# On a Windows build with GDI+ available, the run command would be:
#
# ASAN_OPTIONS="abort_on_error=0:log_path=/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-ico_c/asan_001.log" \
#   /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata \
#   /data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-ico_c/vuln_001.ico \
#   /data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-ico_c/vuln_001_out.c \
#   > /data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-ico_c/vuln_001_result.txt 2>&1 || true

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-ico_c"

echo "SKIPPED: io-gdip-ico GDI+ loader not available on this Linux build." | tee "${POC_DIR}/vuln_001_result.txt"
echo "See vuln_001_notes.md for details." | tee -a "${POC_DIR}/vuln_001_result.txt"
