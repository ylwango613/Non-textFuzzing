#!/usr/bin/env bash
# vuln_001_run.sh — PoC runner for VULN-001 (GdkPixdata RAW decoder heap OOB read)
#
# Two-pronged approach:
#   1. File-based: generate crafted .gdkp and run gdk-pixbuf-pixdata
#      (the GString over-allocation in io-pixdata.c may mask the OOB from ASAN)
#   2. Direct harness: compile & run harness_001.c with a precisely-sized
#      24-byte g_malloc() buffer so ASAN catches the OOB immediately.

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-io_c"
BUILD_TEST="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test"
BINARY="${BUILD_TEST}/bin/gdk-pixbuf-pixdata"
INPUT="${POC_DIR}/vuln_001.gdkp"
OUTPUT_C="${POC_DIR}/vuln_001_out.c"
RESULT_TXT="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG_BASE="${POC_DIR}/asan_001.log"
STATUS_TXT="${POC_DIR}/vuln_001_status.txt"
HARNESS_SRC="${POC_DIR}/harness_001.c"
HARNESS_BIN="${POC_DIR}/harness_001"
HARNESS_ASAN_LOG="${POC_DIR}/asan_harness.log"

# ── Step 1: generate PoC input ─────────────────────────────────────────────
echo "[*] Step 1: generating PoC input file..."
python3 "${POC_DIR}/vuln_001_gen.py"

# ── Step 2: file-based run via gdk-pixbuf-pixdata ──────────────────────────
echo "[*] Step 2: running gdk-pixbuf-pixdata under ASAN (file-based)..."
rm -f "${POC_DIR}"/asan_001.log.*

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_BASE}" \
  "${BINARY}" \
  "${INPUT}" \
  "${OUTPUT_C}" \
  > "${RESULT_TXT}" 2>&1 || true

# ── Step 3: compile and run direct harness ─────────────────────────────────
echo "[*] Step 3: compiling direct harness (harness_001.c)..."
rm -f "${POC_DIR}"/asan_harness.log.*

PKG_CONFIG_PATH="${BUILD_TEST}/lib/pkgconfig" \
gcc -o "${HARNESS_BIN}" "${HARNESS_SRC}" \
    -fsanitize=address,undefined \
    -I"${BUILD_TEST}/include/gdk-pixbuf-2.0" \
    $(pkg-config --cflags glib-2.0 gobject-2.0) \
    -L"${BUILD_TEST}/lib" \
    -lgdk_pixbuf-2.0 -lgobject-2.0 -lglib-2.0 \
    -Wl,-rpath,"${BUILD_TEST}/lib" \
    2>&1 | tee "${POC_DIR}/harness_compile.log"

echo "[*] Running direct harness under ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=${HARNESS_ASAN_LOG}" \
  "${HARNESS_BIN}" \
  >> "${RESULT_TXT}" 2>&1 || true

# ── Step 4: check results ──────────────────────────────────────────────────
echo "[*] Step 4: checking for crash / ASAN report..."

CRASHED=0
ASAN_LOG_FILE=""

# Check program output for crash indicators
if grep -qiE "(segfault|signal|abort|heap.buffer.overflow|stack.buffer.overflow|use.after.free|AddressSanitizer)" \
      "${RESULT_TXT}" 2>/dev/null; then
    CRASHED=1
fi

# Check file-based ASAN logs
for f in "${POC_DIR}"/asan_001.log.*; do
    if [ -f "${f}" ] && [ -s "${f}" ]; then
        CRASHED=1
        ASAN_LOG_FILE="${f}"
        echo "[*] Found ASAN log (file-based): ${f}"
        break
    fi
done

# Check harness ASAN logs
for f in "${POC_DIR}"/asan_harness.log.*; do
    if [ -f "${f}" ] && [ -s "${f}" ]; then
        CRASHED=1
        if [ -z "${ASAN_LOG_FILE}" ]; then
            ASAN_LOG_FILE="${f}"
        fi
        echo "[*] Found ASAN log (harness): ${f}"
        break
    fi
done

echo ""
echo "=== Combined output (${RESULT_TXT}) ==="
cat "${RESULT_TXT}" || true

if [ -n "${ASAN_LOG_FILE}" ] && [ -f "${ASAN_LOG_FILE}" ]; then
    echo ""
    echo "=== ASAN log (${ASAN_LOG_FILE}) ==="
    cat "${ASAN_LOG_FILE}" || true
fi

# ── Step 5: write status ───────────────────────────────────────────────────
echo ""
echo "[*] Step 5: writing status..."

if [ "${CRASHED}" -eq 1 ]; then
    STATUS="VERIFIED_CRASH"
else
    STATUS="UNVERIFIED"
fi

{
    echo "${STATUS}"
    echo ""
    echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Binary: ${BINARY}"
    echo "Harness: ${HARNESS_BIN}"
    echo "Input: ${INPUT} ($(wc -c < "${INPUT}" 2>/dev/null || echo '?') bytes)"
    echo ""
    # List all ASAN logs found
    for f in "${POC_DIR}"/asan_001.log.* "${POC_DIR}"/asan_harness.log.*; do
        if [ -f "${f}" ] && [ -s "${f}" ]; then
            echo "ASAN log: ${f}"
            echo ""
            echo "--- ASAN log (${f}) ---"
            cat "${f}" || true
            echo ""
        fi
    done
    echo "--- Combined program output ---"
    cat "${RESULT_TXT}" || true
} > "${STATUS_TXT}"

echo "[*] Status: ${STATUS}"
echo "[*] Status file written to: ${STATUS_TXT}"
