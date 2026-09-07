#!/bin/bash
# VULN 002 - NULL Pointer Dereference via g_try_malloc Unchecked Return
# Status: SKIPPED (GDI+ loader not available on this Linux build)

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-ico_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"

echo "[SKIPPED] VULN-002: GDI+ ICO NULL Pointer Dereference"
echo "[SKIPPED] This vulnerability is in io-gdip-utils.c (GDI+ Windows loader)."
echo "[SKIPPED] The GDI+ loader is not compiled into this Linux build."
echo "[SKIPPED] No gdip_bitmap_* symbols present in libgdk_pixbuf-2.0."
echo ""

# Generate stub ICO file
python3 "${POC_DIR}/vuln_002_gen.py"

echo ""
echo "[INFO] Attempting binary invocation for completeness (will use native ICO loader, not GDI+ path)..."

ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_002.log" \
  "${BINARY}" \
  "${POC_DIR}/vuln_002.ico" \
  "${POC_DIR}/vuln_002_out.c" \
  > "${POC_DIR}/vuln_002_result.txt" 2>&1 || true

echo "[INFO] Binary exit. See vuln_002_result.txt for output."
echo "[INFO] ASAN log (if any): ${POC_DIR}/asan_002.log*"
echo ""
echo "[RESULT] Status: SKIPPED - GDI+ loader not present on Linux target."
