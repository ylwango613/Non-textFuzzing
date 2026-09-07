#!/usr/bin/env bash
# vuln_001_run.sh - Run the VULN-001 PoC for gdk-pixbuf OFFSET macro overflow
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-scale_c"
BINARY="/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata"
GEN_SCRIPT="${POC_DIR}/vuln_001_gen.py"
TRIGGER_FILE="${POC_DIR}/trigger.bmp"
OUTPUT_FILE="${POC_DIR}/output.pixdata"
STATUS_FILE="${POC_DIR}/vuln_001_status.txt"

export ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan.log"

echo "============================================================"
echo "VULN-001: gdk-pixbuf OFFSET macro signed integer overflow"
echo "File: gdk-pixbuf/gdk-pixbuf-scale.c, line 399"
echo "============================================================"
echo ""

# Step 1: Generate the trigger BMP
echo "[1] Generating trigger BMP..."
python3 "${GEN_SCRIPT}"
echo "[*] Trigger file: ${TRIGGER_FILE}"
echo "[*] File size: $(wc -c < "${TRIGGER_FILE}") bytes"
echo ""

# Step 2: Run gdk-pixbuf-pixdata on the trigger file
echo "[2] Running gdk-pixbuf-pixdata on trigger file..."
echo "[*] Binary: ${BINARY}"
echo "[*] ASAN_OPTIONS=${ASAN_OPTIONS}"
echo ""

set +e
"${BINARY}" "${TRIGGER_FILE}" "${OUTPUT_FILE}" 2>&1
EXIT_CODE=$?
set -e

echo ""
echo "[*] Exit code: ${EXIT_CODE}"

# Step 3: Check for ASAN log output
echo ""
echo "[3] Checking for ASAN output..."
if ls "${POC_DIR}"/asan.log* 2>/dev/null | grep -q .; then
    echo "[!] ASAN log files found:"
    ls -la "${POC_DIR}"/asan.log* 2>/dev/null
    echo "--- ASAN log contents ---"
    cat "${POC_DIR}"/asan.log* 2>/dev/null || true
    echo "-------------------------"
else
    echo "[*] No ASAN log files generated"
fi

# Step 4: Determine status
echo ""
echo "[4] Determining status..."
echo "[*] NOTE: gdk-pixbuf-pixdata does NOT call gdk_pixbuf_rotate_simple()"
echo "[*]       or gdk_pixbuf_flip(). The OFFSET macro overflow in scale.c"
echo "[*]       line 399 cannot be triggered via this binary alone."
echo "[*]       Status: SKIPPED (binary does not exercise vulnerable code path)"

# Write status file
cat > "${STATUS_FILE}" <<'EOF'
SKIPPED
Reason: gdk-pixbuf-pixdata does not call gdk_pixbuf_rotate_simple() or gdk_pixbuf_flip().
The OFFSET macro overflow (gdk-pixbuf-scale.c:399) is only reachable via those functions.
The trigger BMP was generated and the binary was exercised, but the vulnerable code path
was not reached. See vuln_001_notes.md for the real trigger path.
EOF

echo ""
echo "[*] Status written to: ${STATUS_FILE}"
echo "============================================================"
echo "DONE"
echo "============================================================"
